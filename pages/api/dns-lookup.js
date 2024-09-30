export const runtime = 'edge';  // Enable Edge Runtime for Cloudflare Pages

export default async function handler(req, res) {
    const { domain } = req.query;

    if (!domain) {
        return res.status(400).json({ error: "Domain is required" });
    }

    // Helper function to query specific DNS record types
    const fetchDnsRecords = async (domain, type) => {
        try {
            const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=${type}`, {
                headers: {
                    'Accept': 'application/dns-json'
                }
            });

            if (!response.ok) {
                throw new Error(`Error fetching ${type} records: ${response.statusText}`);
            }

            const data = await response.json();
            return data.Answer || []; // Return empty array if no records found
        } catch (error) {
            console.error(`Error querying ${type} records for ${domain}:`, error);
            return []; // Return empty array if there's an error
        }
    };

    try {
        // List of all DNS record types we want to query
        const recordTypes = [
            'A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 
            'SOA', 'SRV', 'TXT', 'NAPTR', 'DNAME', 
            'DS', 'RRSIG', 'DNSKEY', 'CAA'
        ];

        // Fetch all DNS record types in parallel
        const dnsPromises = recordTypes.map(type => fetchDnsRecords(domain, type));
        const allDnsResults = await Promise.all(dnsPromises);

        // Fetch DKIM records by querying common DKIM selectors
        const dkimSelectors = [
            'default', 'google', 'dkim', 'selector1',
            'selector2', 'mail', 'email', 's1', 
            's2', 's3', 'smtp', 'postfix', 
            'default._domainkey', 'sec1', 's0', 
            's1._domainkey', '1', 'dkim1', 'd1',
            'key1._domainkey', 'mail._domainkey', 
            'smtp._domainkey', '_domainkey', '_mail._domainkey'
        ];

        const dkimPromises = dkimSelectors.map(selector => 
            fetchDnsRecords(`${selector}._domainkey.${domain}`, 'TXT')
        );
        const dkimResults = await Promise.all(dkimPromises);

        // Fetch DMARC record explicitly from the `_dmarc` subdomain
        const dmarcRecord = await fetchDnsRecords(`_dmarc.${domain}`, 'TXT');

        // Combine all DNS results with DKIM and DMARC records
        const allRecords = [
            ...allDnsResults.flat(), 
            ...dkimResults.flat(), 
            ...dmarcRecord
        ];

        // If no records are found, return a 404 response
        if (allRecords.length === 0) {
            return res.status(404).json({ error: "No DNS records found" });
        }

        // Map and format the records
        const formattedRecords = allRecords.map(record => ({
            type: record.type,
            value: record.data,
            ttl: record.TTL
        }));

        return res.status(200).json(formattedRecords);
    } catch (error) {
        console.error('DNS lookup error:', error);
        return res.status(500).json({ error: "Error resolving DNS" });
    }
}
