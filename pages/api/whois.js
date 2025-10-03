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

    // Use WHOIS API service - we'll use whoisjsonapi.com which has a free tier
    const whoisResponse = await fetch(
      `https://whoisjsonapi.com/v1/${encodeURIComponent(cleanDomain)}`,
      {
        headers: {
          'Accept': 'application/json'
        }
      }
    );

    if (!whoisResponse.ok) {
      // Fallback to rdap.org (Registration Data Access Protocol)
      const rdapResponse = await fetch(
        `https://rdap.org/domain/${encodeURIComponent(cleanDomain)}`,
        {
          headers: {
            'Accept': 'application/json'
          }
        }
      );

      if (!rdapResponse.ok) {
        throw new Error('WHOIS lookup failed');
      }

      const rdapData = await rdapResponse.json();

      // Parse RDAP response
      const registrar = rdapData.entities?.find(e => e.roles?.includes('registrar'));
      const registrant = rdapData.entities?.find(e => e.roles?.includes('registrant'));

      return new Response(JSON.stringify({
        domain: cleanDomain,
        source: 'rdap',
        registrar: registrar?.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3] || 'Unknown',
        registrant: registrant?.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3] || 'Redacted',
        createdDate: rdapData.events?.find(e => e.eventAction === 'registration')?.eventDate || null,
        updatedDate: rdapData.events?.find(e => e.eventAction === 'last changed')?.eventDate || null,
        expiryDate: rdapData.events?.find(e => e.eventAction === 'expiration')?.eventDate || null,
        nameServers: rdapData.nameservers?.map(ns => ns.ldhName) || [],
        status: rdapData.status || [],
        dnssec: rdapData.secureDNS?.delegationSigned ? 'Signed' : 'Unsigned'
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const whoisData = await whoisResponse.json();

    // Parse whoisjsonapi.com response
    return new Response(JSON.stringify({
      domain: cleanDomain,
      source: 'whois',
      registrar: whoisData.registrar || 'Unknown',
      registrant: whoisData.registrant?.organization || whoisData.registrant?.name || 'Redacted',
      createdDate: whoisData.created || null,
      updatedDate: whoisData.updated || null,
      expiryDate: whoisData.expires || null,
      nameServers: whoisData.nameservers || [],
      status: whoisData.status || [],
      dnssec: whoisData.dnssec || 'Unknown'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    return new Response(JSON.stringify({
      error: 'WHOIS lookup failed',
      message: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
