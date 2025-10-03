export const runtime = 'edge';

export default async function handler(req) {
  const { searchParams } = new URL(req.url);
  const domain = searchParams.get('domain');

  if (!domain) {
    return new Response(JSON.stringify({ error: 'Domain parameter is required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  try {
    // Clean domain
    const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0];

    // Query for DNSSEC-related records using Cloudflare DNS
    const recordTypes = [
      { type: 43, name: 'DS' },      // Delegation Signer
      { type: 48, name: 'DNSKEY' },  // DNS Key
      { type: 46, name: 'RRSIG' },   // Resource Record Signature
      { type: 47, name: 'NSEC' },    // Next Secure
      { type: 50, name: 'NSEC3' },   // Next Secure v3
    ];

    const promises = recordTypes.map(({ type, name }) =>
      fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(cleanDomain)}&type=${type}`, {
        headers: { 'Accept': 'application/dns-json' }
      })
      .then(res => res.json())
      .then(data => ({ type: name, records: data.Answer || [] }))
      .catch(() => ({ type: name, records: [] }))
    );

    const results = await Promise.all(promises);

    // Check if DNSSEC is configured
    const hasDS = results.find(r => r.type === 'DS')?.records.length > 0;
    const hasDNSKEY = results.find(r => r.type === 'DNSKEY')?.records.length > 0;
    const hasRRSIG = results.find(r => r.type === 'RRSIG')?.records.length > 0;
    const hasNSEC = results.find(r => r.type === 'NSEC')?.records.length > 0;
    const hasNSEC3 = results.find(r => r.type === 'NSEC3')?.records.length > 0;

    // Determine DNSSEC status
    let status = 'unsigned';
    let validation = 'not_validated';
    let details = [];

    if (hasDS || hasDNSKEY || hasRRSIG) {
      status = 'signed';

      if (hasDS && hasDNSKEY && hasRRSIG) {
        validation = 'fully_signed';
        details.push('Domain has complete DNSSEC chain (DS, DNSKEY, RRSIG)');
      } else if (hasDS && hasDNSKEY) {
        validation = 'partially_signed';
        details.push('Domain has DS and DNSKEY records');
        if (!hasRRSIG) details.push('Missing RRSIG records');
      } else if (hasRRSIG) {
        validation = 'signatures_only';
        details.push('Domain has RRSIG records but may be missing DS/DNSKEY');
      }

      if (hasNSEC) details.push('Using NSEC for authenticated denial');
      if (hasNSEC3) details.push('Using NSEC3 for authenticated denial');
    } else {
      details.push('No DNSSEC records found - domain is not signed');
    }

    // Parse DS records for algorithm info
    const dsRecords = results.find(r => r.type === 'DS')?.records.map(record => {
      const parts = record.data.split(' ');
      return {
        keyTag: parts[0],
        algorithm: parts[1],
        digestType: parts[2],
        digest: parts[3]
      };
    }) || [];

    // Parse DNSKEY records
    const dnskeyRecords = results.find(r => r.type === 'DNSKEY')?.records.map(record => {
      const parts = record.data.split(' ');
      return {
        flags: parts[0],
        protocol: parts[1],
        algorithm: parts[2],
        publicKey: parts[3]?.substring(0, 20) + '...' // Truncate for display
      };
    }) || [];

    return new Response(JSON.stringify({
      domain: cleanDomain,
      status,
      validation,
      details,
      records: {
        ds: dsRecords,
        dnskey: dnskeyRecords,
        hasRRSIG: hasRRSIG,
        hasNSEC: hasNSEC,
        hasNSEC3: hasNSEC3
      },
      summary: {
        isSigned: status === 'signed',
        chainComplete: validation === 'fully_signed',
        recordCount: {
          DS: results.find(r => r.type === 'DS')?.records.length || 0,
          DNSKEY: results.find(r => r.type === 'DNSKEY')?.records.length || 0,
          RRSIG: results.find(r => r.type === 'RRSIG')?.records.length || 0,
          NSEC: results.find(r => r.type === 'NSEC')?.records.length || 0,
          NSEC3: results.find(r => r.type === 'NSEC3')?.records.length || 0
        }
      }
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    return new Response(JSON.stringify({
      error: 'DNSSEC validation failed',
      message: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
