import https from 'https';

// Helper function to get certificate from a domain
function getCertificate(hostname) {
    return new Promise((resolve, reject) => {
        const options = {
            host: hostname,
            port: 443,
            method: 'GET',
            rejectUnauthorized: false,
            agent: false,
            timeout: 5000, // 5 second timeout
        };

        const req = https.request(options, (response) => {
            const cert = response.socket.getPeerCertificate();

            if (!cert || Object.keys(cert).length === 0) {
                reject(new Error('No certificate found'));
                return;
            }

            const now = new Date();
            const expiryDate = new Date(cert.valid_to);
            const issueDate = new Date(cert.valid_from);
            const daysUntilExpiry = Math.floor((expiryDate - now) / (1000 * 60 * 60 * 24));

            resolve({
                hostname,
                issuer: cert.issuer?.O || cert.issuer?.CN || 'Unknown',
                commonName: cert.subject?.CN || hostname,
                notBefore: issueDate.toISOString(),
                notAfter: expiryDate.toISOString(),
                serialNumber: cert.serialNumber,
                subjectAltNames: cert.subjectaltname ? cert.subjectaltname.split(', ').map(s => s.replace('DNS:', '')) : [],
                daysUntilExpiry,
            });

            response.socket.end();
        });

        req.on('error', (error) => {
            reject(error);
        });

        req.on('timeout', () => {
            req.destroy();
            reject(new Error('Request timeout'));
        });

        req.end();
    });
}

export default async function handler(req, res) {
    const { domain, offset = 0 } = req.query;

    if (!domain) {
        return res.status(400).json({ error: "Domain is required" });
    }

    try {
        // Clean domain (remove protocol, www, paths)
        const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0];
        const startOffset = parseInt(offset) || 0;
        const batchSize = 10;

        // First, get DNS A records to find actual hosts
        const dnsResponse = await fetch(`https://cloudflare-dns.com/dns-query?name=${cleanDomain}&type=A`, {
            headers: {
                'Accept': 'application/dns-json',
            },
        });

        const hostsToCheck = [cleanDomain]; // Always check the main domain

        // Add common subdomains to check
        const commonSubdomains = [
            'www', 'mail', 'smtp', 'pop', 'imap', 'ftp', 'webmail',
            'remote', 'blog', 'shop', 'store', 'admin', 'portal',
            'api', 'dev', 'staging', 'test', 'demo', 'app'
        ];

        // Check which common subdomains resolve
        const subdomainPromises = commonSubdomains.map(async (subdomain) => {
            try {
                const subdomainHost = `${subdomain}.${cleanDomain}`;
                const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${subdomainHost}&type=A`, {
                    headers: { 'Accept': 'application/dns-json' },
                });
                if (response.ok) {
                    const data = await response.json();
                    if (data.Answer && data.Answer.length > 0) {
                        return subdomainHost;
                    }
                }
            } catch (err) {
                // Ignore
            }
            return null;
        });

        const resolvedSubdomains = await Promise.all(subdomainPromises);
        resolvedSubdomains.forEach(host => {
            if (host && !hostsToCheck.includes(host)) {
                hostsToCheck.push(host);
            }
        });

        if (dnsResponse.ok) {
            const dnsData = await dnsResponse.json();

            // Get A record IPs and do reverse DNS lookups
            if (dnsData.Answer) {
                const aRecords = dnsData.Answer.filter(record => record.type === 1); // A records

                // Do reverse DNS for each A record IP (limit to 100 total)
                const reversePromises = aRecords.slice(0, 100).map(async (record) => {
                    try {
                        const ip = record.data;
                        // Reverse DNS lookup
                        const octets = ip.split('.');
                        const reverseIp = `${octets[3]}.${octets[2]}.${octets[1]}.${octets[0]}.in-addr.arpa`;

                        const ptrResponse = await fetch(`https://cloudflare-dns.com/dns-query?name=${reverseIp}&type=PTR`, {
                            headers: {
                                'Accept': 'application/dns-json',
                            },
                        });

                        if (ptrResponse.ok) {
                            const ptrData = await ptrResponse.json();
                            if (ptrData.Answer && ptrData.Answer.length > 0) {
                                const hostname = ptrData.Answer[0].data.replace(/\.$/, ''); // Remove trailing dot
                                return hostname;
                            }
                        }
                    } catch (err) {
                        // Ignore reverse DNS errors
                    }
                    return null;
                });

                const reverseHosts = await Promise.all(reversePromises);
                reverseHosts.forEach(host => {
                    if (host && !hostsToCheck.includes(host)) {
                        hostsToCheck.push(host);
                    }
                });
            }
        }

        // Get the batch to check (10 hosts at a time)
        const totalHosts = Math.min(hostsToCheck.length, 100);
        const hostsInBatch = hostsToCheck.slice(startOffset, startOffset + batchSize);
        const hasMore = startOffset + batchSize < totalHosts;

        // Check the current batch in parallel
        const results = await Promise.allSettled(
            hostsInBatch.map(hostname => getCertificate(hostname))
        );

        // Filter successful results and deduplicate by serial number
        const seenSerials = new Set();
        const certificates = [];

        results.forEach((result) => {
            if (result.status === 'fulfilled') {
                const cert = result.value;
                if (!seenSerials.has(cert.serialNumber)) {
                    seenSerials.add(cert.serialNumber);
                    certificates.push(cert);
                }
            }
        });

        if (certificates.length === 0) {
            return res.status(404).json({
                error: "No certificates found for this domain or any of its subdomains"
            });
        }

        // Sort by expiry date (most recent first)
        certificates.sort((a, b) => new Date(b.notBefore) - new Date(a.notBefore));

        const mostRecent = certificates[0];
        const now = new Date();
        const expiryDate = new Date(mostRecent.notAfter);
        const daysUntilExpiry = Math.floor((expiryDate - now) / (1000 * 60 * 60 * 24));

        res.status(200).json({
            domain: cleanDomain,
            certificates: certificates.map(cert => ({
                issuer: cert.issuer,
                commonName: cert.commonName,
                notBefore: cert.notBefore,
                notAfter: cert.notAfter,
                serialNumber: cert.serialNumber,
                subjectAltNames: cert.subjectAltNames,
            })),
            mostRecentExpiry: {
                date: expiryDate.toISOString(),
                daysRemaining: daysUntilExpiry,
                isExpired: daysUntilExpiry < 0,
                isExpiringSoon: daysUntilExpiry < 30 && daysUntilExpiry >= 0,
            },
            pagination: {
                offset: startOffset,
                limit: batchSize,
                total: totalHosts,
                hasMore,
                nextOffset: hasMore ? startOffset + batchSize : null,
            }
        });

    } catch (error) {
        console.error('SSL check error:', error);
        res.status(500).json({
            error: "Error checking SSL certificate",
            details: error.message
        });
    }
}
