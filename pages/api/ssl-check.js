export const runtime = 'edge'; // Enable Edge Runtime for Cloudflare Pages

export default async function handler(req) {
    const { searchParams } = new URL(req.url);
    const domain = searchParams.get('domain');

    if (!domain) {
        return new Response(JSON.stringify({ error: "Domain is required" }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
        });
    }

    try {
        // Clean domain (remove protocol, www, paths)
        const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0];

        // Fetch SSL certificate info via API
        // Using crt.sh as a free certificate transparency log API
        const crtResponse = await fetch(`https://crt.sh/?q=${encodeURIComponent(cleanDomain)}&output=json`, {
            headers: {
                'Accept': 'application/json',
            },
        });

        if (!crtResponse.ok) {
            throw new Error('Failed to fetch certificate info');
        }

        const certificates = await crtResponse.json();

        if (!certificates || certificates.length === 0) {
            return new Response(JSON.stringify({ error: "No certificates found" }), {
                status: 404,
                headers: { 'Content-Type': 'application/json' },
            });
        }

        // Sort certificates by notBefore date (most recently issued first)
        // This ensures we get the current/active certificate, not just recently logged ones
        const sortedCerts = certificates.sort((a, b) =>
            new Date(b.not_before) - new Date(a.not_before)
        );

        // Get unique certificates by serial number (remove duplicates)
        const uniqueCerts = [];
        const seenSerials = new Set();

        for (const cert of sortedCerts) {
            if (!seenSerials.has(cert.serial_number)) {
                seenSerials.add(cert.serial_number);
                uniqueCerts.push({
                    issuer: cert.issuer_name,
                    commonName: cert.common_name,
                    notBefore: cert.not_before,
                    notAfter: cert.not_after,
                    serialNumber: cert.serial_number,
                    entryTimestamp: cert.entry_timestamp,
                });

                // Only return top 5 most recent
                if (uniqueCerts.length >= 5) break;
            }
        }

        // Calculate days until expiry for the most recent cert
        const mostRecent = uniqueCerts[0];
        const expiryDate = new Date(mostRecent.notAfter);
        const now = new Date();
        const daysUntilExpiry = Math.floor((expiryDate - now) / (1000 * 60 * 60 * 24));

        return new Response(JSON.stringify({
            domain: cleanDomain,
            certificates: uniqueCerts,
            mostRecentExpiry: {
                date: mostRecent.notAfter,
                daysRemaining: daysUntilExpiry,
                isExpired: daysUntilExpiry < 0,
                isExpiringSoon: daysUntilExpiry < 30 && daysUntilExpiry >= 0,
            }
        }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
        });

    } catch (error) {
        console.error('SSL check error:', error);
        return new Response(JSON.stringify({
            error: "Error checking SSL certificate",
            details: error.message
        }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' },
        });
    }
}
