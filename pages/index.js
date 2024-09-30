"use client"

import { useState } from 'react';
import InputSection from '../components/InputSection';
import TableSection from '../components/TableSection';
import SecurityInsights from '../components/SecurityInsights';
import { Button } from "@nextui-org/button";
import { Input } from "@nextui-org/input"; // Ensure this is included
import { Download } from 'lucide-react';
import Link from 'next/link';

// Mapping all DNS record types
const dnsRecordTypeMap = {
  1: 'A',
  5: 'CNAME',
  15: 'MX',
  16: 'TXT',
  28: 'AAAA',  // IPv6
  2: 'NS',  // Name Server
  12: 'PTR',  // Pointer
  6: 'SOA',  // Start of Authority
  33: 'SRV',  // Service Locator
  35: 'NAPTR',  // Naming Authority Pointer
  39: 'DNAME',  // Delegation Name
  43: 'DS',  // Delegation Signer (DNSSEC)
  46: 'RRSIG',  // DNSSEC Signature
  48: 'DNSKEY',  // DNSSEC Public Key
  257: 'CAA',  // Certificate Authority Authorization
}

export default function DnsLookupTool() {
  const [domain, setDomain] = useState('');
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(false);
  const [filterValue, setFilterValue] = useState("");

  const handleLookup = async () => {
    if (!domain) return;

    setLoading(true);
    try {
      const response = await fetch(`/api/dns-lookup?domain=${domain}`);
      const data = await response.json();

      if (response.ok) {
        const mappedRecords = data.map(record => ({
          type: dnsRecordTypeMap[record.type] || record.type,
          value: record.value,
          ttl: record.ttl
        }));
        setRecords(mappedRecords);
      } else {
        console.error('Error fetching DNS records:', data.error);
      }
    } catch (error) {
      console.error('Error fetching DNS records:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleExport = () => {
    const csv = [
      ['Type', 'Value', 'TTL'],
      ...records.map(record => [record.type, record.value, record.ttl])
    ].map(row => row.join(',')).join('\n');

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dns_records_${domain}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const checkSecurity = () => {
    const hasSPF = records.some(record => record.type === 'TXT' && record.value.includes('v=spf1'));
    const hasDKIM = records.some(record => record.type === 'TXT' && record.value.includes('v=DKIM1'));
    const hasDMARC = records.some(record => record.type === 'TXT' && record.value.includes('v=DMARC1'));

    return { spf: hasSPF, dkim: hasDKIM, dmarc: hasDMARC };
  };

  const securityStatus = checkSecurity();

  return (
    <div className="max-w-4xl mx-auto p-6 bg-white dark:bg-gray-900 rounded-lg shadow-lg">
      <h1 className="text-4xl font-bold text-gray-800 dark:text-white mb-6 text-center">DNS Lookup Tool</h1>
      
      <InputSection domain={domain} setDomain={setDomain} handleLookup={handleLookup} loading={loading} />
      
      {records.length > 0 && (
        <>
          <div className="flex justify-between items-center mt-6">
            <Button onClick={handleExport} className="px-4 py-2 bg-green-500 hover:bg-green-600 text-white rounded-lg transition duration-200">
              <Download className="mr-2 h-4 w-4" />
              Export CSV
            </Button>
            <Input
              className="w-full md:w-1/3 border border-gray-300 dark:border-gray-600 p-3 rounded-lg bg-gray-50 dark:bg-gray-800 text-gray-700 dark:text-white"
              type="text"
              placeholder="Filter records"
              value={filterValue}
              onChange={(e) => setFilterValue(e.target.value)}
            />
          </div>

          <TableSection records={records} filterValue={filterValue} />

          <div className="text-sm text-gray-500 dark:text-gray-400 mt-4">
            {records.length} records found
          </div>

          <SecurityInsights securityStatus={securityStatus} />

          {/* Debug link */}
          <div className="mt-6">
            <Link href="/debug" className="text-blue-500 hover:text-blue-700">Go to Debug Page</Link>
          </div>
        </>
      )}
    </div>
  );
}
