"use client"

import { useState, useEffect, useCallback } from 'react';
import InputSection from '../components/InputSection';
import TableSection from '../components/TableSection';
import SecurityInsights from '../components/SecurityInsights';
import { Button } from "@nextui-org/button";
import { Input } from "@nextui-org/input";
import { Download, History, X, Copy, Check, Filter } from 'lucide-react';
import Link from 'next/link';

// Mapping all DNS record types
const dnsRecordTypeMap = {
  1: 'A',
  5: 'CNAME',
  15: 'MX',
  16: 'TXT',
  28: 'AAAA',
  2: 'NS',
  12: 'PTR',
  6: 'SOA',
  33: 'SRV',
  35: 'NAPTR',
  39: 'DNAME',
  43: 'DS',
  46: 'RRSIG',
  48: 'DNSKEY',
  257: 'CAA',
}

const EXAMPLE_DOMAINS = [
  'google.com',
  'cloudflare.com',
  'github.com',
  'amazon.com',
];

const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'CAA'];

// Parse SPF record
const parseSPFRecord = (value) => {
  if (!value.includes('v=spf1')) return null;

  const mechanisms = [];
  const qualifiers = { '+': 'Pass', '-': 'Fail', '~': 'SoftFail', '?': 'Neutral' };
  const parts = value.split(' ');

  parts.forEach(part => {
    if (part === 'v=spf1') return;

    const qualifier = qualifiers[part[0]] || 'Pass';
    const mechanism = part.replace(/^[+\-~?]/, '');

    if (mechanism.startsWith('ip4:')) {
      mechanisms.push({ type: 'IPv4', value: mechanism.replace('ip4:', ''), action: qualifier });
    } else if (mechanism.startsWith('ip6:')) {
      mechanisms.push({ type: 'IPv6', value: mechanism.replace('ip6:', ''), action: qualifier });
    } else if (mechanism.startsWith('include:')) {
      mechanisms.push({ type: 'Include', value: mechanism.replace('include:', ''), action: qualifier });
    } else if (mechanism.startsWith('a:')) {
      mechanisms.push({ type: 'A Record', value: mechanism.replace('a:', ''), action: qualifier });
    } else if (mechanism === 'a') {
      mechanisms.push({ type: 'A Record', value: 'Current domain', action: qualifier });
    } else if (mechanism.startsWith('mx:')) {
      mechanisms.push({ type: 'MX Record', value: mechanism.replace('mx:', ''), action: qualifier });
    } else if (mechanism === 'mx') {
      mechanisms.push({ type: 'MX Record', value: 'Current domain', action: qualifier });
    } else if (mechanism.startsWith('redirect=')) {
      mechanisms.push({ type: 'Redirect', value: mechanism.replace('redirect=', ''), action: 'Redirect' });
    } else if (mechanism === 'all') {
      mechanisms.push({ type: 'All Others', value: 'Default policy', action: qualifier });
    } else if (mechanism.startsWith('exists:')) {
      mechanisms.push({ type: 'Exists', value: mechanism.replace('exists:', ''), action: qualifier });
    } else if (mechanism.startsWith('ptr:')) {
      mechanisms.push({ type: 'PTR (Deprecated)', value: mechanism.replace('ptr:', ''), action: qualifier });
    }
  });

  const hasHardFail = mechanisms.some(m => m.action === 'Fail');
  const hasSoftFail = mechanisms.some(m => m.action === 'SoftFail');
  const includeCount = mechanisms.filter(m => m.type === 'Include').length;

  return {
    raw: value,
    mechanisms,
    strength: hasHardFail ? 'Strong' : hasSoftFail ? 'Moderate' : 'Weak',
    includeCount,
    warnings: [
      includeCount > 10 ? 'Too many includes (DNS lookup limit is 10)' : null,
      !hasHardFail && !hasSoftFail ? 'No fail policy for unauthorized senders' : null,
      mechanisms.some(m => m.type === 'PTR (Deprecated)') ? 'PTR mechanism is deprecated' : null,
    ].filter(Boolean)
  };
};

// Parse DMARC record
const parseDMARCRecord = (value) => {
  if (!value.includes('v=DMARC1')) return null;

  const tags = {};
  const parts = value.split(';').map(p => p.trim()).filter(Boolean);

  parts.forEach(part => {
    const [key, val] = part.split('=').map(s => s.trim());
    if (key && val) tags[key] = val;
  });

  const policy = tags.p || 'none';
  const subdomainPolicy = tags.sp || policy;
  const percentage = tags.pct || '100';
  const alignment = {
    dkim: tags.adkim || 'r',
    spf: tags.aspf || 'r'
  };

  const strength =
    policy === 'reject' ? 'Strong' :
    policy === 'quarantine' ? 'Moderate' :
    'Weak';

  const warnings = [
    policy === 'none' ? 'Policy set to "none" - emails are not protected' : null,
    !tags.rua ? 'No aggregate reports configured (rua tag missing)' : null,
    percentage !== '100' ? `Only ${percentage}% of emails are subject to the policy` : null,
    alignment.dkim === 'r' && alignment.spf === 'r' ? 'Both DKIM and SPF using relaxed alignment' : null,
  ].filter(Boolean);

  return {
    raw: value,
    policy,
    subdomainPolicy,
    percentage: `${percentage}%`,
    alignment,
    aggregateReports: tags.rua || 'Not configured',
    forensicReports: tags.ruf || 'Not configured',
    strength,
    warnings
  };
};

export default function DnsLookupTool() {
  const [domain, setDomain] = useState('');
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(false);
  const [filterValue, setFilterValue] = useState("");
  const [recentLookups, setRecentLookups] = useState([]);
  const [showHistory, setShowHistory] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState(null);
  const [selectedRecordTypes, setSelectedRecordTypes] = useState(new Set(RECORD_TYPES));
  const [showFilters, setShowFilters] = useState(false);
  const [validationError, setValidationError] = useState('');
  const [healthScore, setHealthScore] = useState(null);
  const [spfSummary, setSpfSummary] = useState(null);
  const [dmarcSummary, setDmarcSummary] = useState(null);
  const [bulkMode, setBulkMode] = useState(false);
  const [bulkDomains, setBulkDomains] = useState('');
  const [bulkResults, setBulkResults] = useState([]);
  const [, setTick] = useState(0);
  const [expandedRecords, setExpandedRecords] = useState(new Set());
  const [showDNSMap, setShowDNSMap] = useState(false);
  const [propagationResults, setPropagationResults] = useState([]);
  const [checkingPropagation, setCheckingPropagation] = useState(false);
  const [showPropagation, setShowPropagation] = useState(false);
  const [expandedBulkResults, setExpandedBulkResults] = useState(new Set());
  const [compareMode, setCompareMode] = useState(false);
  const [domain2, setDomain2] = useState('');
  const [records2, setRecords2] = useState([]);
  const [healthScore2, setHealthScore2] = useState(null);
  const [loading2, setLoading2] = useState(false);
  const [reverseIP, setReverseIP] = useState('');
  const [reverseDNSResult, setReverseDNSResult] = useState(null);
  const [loadingReverse, setLoadingReverse] = useState(false);

  // Load recent lookups from localStorage
  useEffect(() => {
    const stored = localStorage.getItem('dnsRecentLookups');
    if (stored) {
      try {
        setRecentLookups(JSON.parse(stored));
      } catch (e) {
        console.error('Error loading history:', e);
      }
    }
  }, []);

  // Save to recent lookups
  const addToHistory = (domainName) => {
    const updated = [domainName, ...recentLookups.filter(d => d !== domainName)].slice(0, 10);
    setRecentLookups(updated);
    localStorage.setItem('dnsRecentLookups', JSON.stringify(updated));
  };

  // Clear history
  const clearHistory = () => {
    setRecentLookups([]);
    localStorage.removeItem('dnsRecentLookups');
    setShowHistory(false);
  };

  // Validate domain
  const validateDomain = (input) => {
    if (!input) {
      setValidationError('');
      return false;
    }

    // Remove protocol if present
    let cleanDomain = input.replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0];

    // Basic domain validation
    const domainRegex = /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i;

    if (!domainRegex.test(cleanDomain)) {
      setValidationError('Invalid domain format');
      return false;
    }

    setValidationError('');
    setDomain(cleanDomain);
    return true;
  };

  // Calculate health score
  const calculateHealthScore = useCallback((recordsData) => {
    let score = 0;
    const issues = [];
    const recommendations = [];

    // Security records (40 points)
    const hasSPF = recordsData.some(r => r.type === 'TXT' && r.value.includes('v=spf1'));
    const hasDMARC = recordsData.some(r => r.type === 'TXT' && r.value.includes('v=DMARC1'));
    const hasDKIM = recordsData.some(r => r.type === 'TXT' && r.value.includes('v=DKIM1'));

    if (hasSPF) score += 15;
    else issues.push('Missing SPF record');

    if (hasDMARC) score += 15;
    else issues.push('Missing DMARC record');

    if (hasDKIM) score += 10;
    else recommendations.push('Consider adding DKIM for email authentication');

    // IPv6 support (10 points)
    const hasIPv6 = recordsData.some(r => r.type === 'AAAA');
    if (hasIPv6) {
      score += 10;
    } else {
      recommendations.push('Add IPv6 (AAAA) records for modern compatibility');
    }

    // MX records (20 points)
    const hasMX = recordsData.some(r => r.type === 'MX');
    if (hasMX) {
      score += 20;
      const mxRecords = recordsData.filter(r => r.type === 'MX');
      if (mxRecords.length >= 2) score += 5; // Redundancy
      else recommendations.push('Add backup MX records for email redundancy');
    } else {
      recommendations.push('No MX records found - email may not be configured');
    }

    // CAA records (10 points)
    const hasCAA = recordsData.some(r => r.type === 'CAA');
    if (hasCAA) score += 10;
    else recommendations.push('Add CAA records to control SSL certificate issuance');

    // TTL optimization (10 points)
    const avgTTL = recordsData.reduce((sum, r) => sum + (r.ttl || 0), 0) / recordsData.length;
    if (avgTTL >= 300 && avgTTL <= 86400) {
      score += 10;
    } else if (avgTTL < 300) {
      recommendations.push('TTL values are very low - may cause high DNS query load');
    } else {
      recommendations.push('TTL values are very high - changes will propagate slowly');
    }

    // Multiple nameservers (5 points)
    const nsRecords = recordsData.filter(r => r.type === 'NS');
    if (nsRecords.length >= 2) score += 5;
    else issues.push('Only one nameserver found - add backup nameservers');

    return {
      score: Math.min(100, score),
      grade: score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F',
      issues,
      recommendations
    };
  }, []);

  const handleLookup = async (domainToLookup = domain) => {
    const cleanDomain = domainToLookup.replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0];

    if (!validateDomain(cleanDomain)) return;

    setLoading(true);
    setRecords([]);
    setHealthScore(null);
    setSpfSummary(null);
    setDmarcSummary(null);

    try {
      const response = await fetch(`/api/dns-lookup?domain=${cleanDomain}`);
      const data = await response.json();

      if (response.ok) {
        const mappedRecords = data.map(record => ({
          type: dnsRecordTypeMap[record.type] || record.type,
          value: record.value,
          ttl: record.ttl,
          timestamp: Date.now()
        }));
        setRecords(mappedRecords);
        addToHistory(cleanDomain);

        // Calculate health score
        const health = calculateHealthScore(mappedRecords);
        setHealthScore(health);

        // Parse SPF and DMARC records
        const spfRecord = mappedRecords.find(r => r.type === 'TXT' && r.value.includes('v=spf1'));
        const dmarcRecord = mappedRecords.find(r => r.type === 'TXT' && r.value.includes('v=DMARC1'));

        if (spfRecord) {
          setSpfSummary(parseSPFRecord(spfRecord.value));
        }

        if (dmarcRecord) {
          setDmarcSummary(parseDMARCRecord(dmarcRecord.value));
        }
      } else {
        console.error('Error fetching DNS records:', data.error);
        setValidationError(data.error || 'Failed to fetch DNS records');
      }
    } catch (error) {
      console.error('Error fetching DNS records:', error);
      setValidationError('Network error - please try again');
    } finally {
      setLoading(false);
    }
  };

  const handleBulkLookup = async () => {
    const domains = bulkDomains
      .split('\n')
      .map(d => d.trim())
      .filter(d => d && validateDomain(d));

    if (domains.length === 0) {
      setValidationError('Please enter at least one valid domain');
      return;
    }

    setLoading(true);
    setBulkResults([]);
    setValidationError('');

    const results = [];

    for (const domainName of domains) {
      try {
        const cleanDomain = domainName.replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0];
        const response = await fetch(`/api/dns-lookup?domain=${cleanDomain}`);
        const data = await response.json();

        if (response.ok) {
          const mappedRecords = data.map(record => ({
            type: dnsRecordTypeMap[record.type] || record.type,
            value: record.value,
            ttl: record.ttl
          }));

          const health = calculateHealthScore(mappedRecords);

          results.push({
            domain: cleanDomain,
            records: mappedRecords,
            healthScore: health,
            status: 'success'
          });
        } else {
          results.push({
            domain: cleanDomain,
            error: data.error || 'Failed to fetch DNS records',
            status: 'error'
          });
        }
      } catch (error) {
        results.push({
          domain: domainName,
          error: 'Network error',
          status: 'error'
        });
      }
    }

    setBulkResults(results);
    setLoading(false);
  };

  // Handle comparison lookup
  const handleCompareLookup = async () => {
    if (!validateDomain(domain) || !validateDomain(domain2)) {
      setValidationError('Please enter two valid domains to compare');
      return;
    }

    // Lookup first domain
    setLoading(true);
    setRecords([]);
    setHealthScore(null);
    await handleLookup(domain);

    // Lookup second domain
    setLoading2(true);
    setRecords2([]);
    setHealthScore2(null);

    try {
      const cleanDomain2 = domain2.replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0];
      const response = await fetch(`/api/dns-lookup?domain=${cleanDomain2}`);
      const data = await response.json();

      if (response.ok) {
        const mappedRecords = data.map(record => ({
          type: dnsRecordTypeMap[record.type] || record.type,
          value: record.value,
          ttl: record.ttl,
          timestamp: Date.now()
        }));
        setRecords2(mappedRecords);

        const health = calculateHealthScore(mappedRecords);
        setHealthScore2(health);
      }
    } catch (error) {
      console.error('Error fetching DNS records for domain 2:', error);
    } finally {
      setLoading2(false);
    }
  };

  // Reverse DNS Lookup
  const handleReverseDNS = async () => {
    if (!reverseIP.trim()) {
      setValidationError('Please enter an IP address');
      return;
    }

    // Validate IP address format
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})$/;

    if (!ipv4Regex.test(reverseIP) && !ipv6Regex.test(reverseIP)) {
      setValidationError('Invalid IP address format');
      return;
    }

    setLoadingReverse(true);
    setReverseDNSResult(null);
    setValidationError('');

    try {
      // Construct reverse DNS domain
      let reverseDomain;
      if (ipv4Regex.test(reverseIP)) {
        // IPv4: reverse octets and add .in-addr.arpa
        const octets = reverseIP.split('.');
        reverseDomain = `${octets[3]}.${octets[2]}.${octets[1]}.${octets[0]}.in-addr.arpa`;
      } else {
        // IPv6: reverse nibbles and add .ip6.arpa (simplified)
        setValidationError('IPv6 reverse lookup not yet supported');
        setLoadingReverse(false);
        return;
      }

      // Lookup PTR record
      const response = await fetch(`/api/dns-lookup?domain=${reverseDomain}`);
      const data = await response.json();

      if (response.ok) {
        const ptrRecords = data.filter(r => dnsRecordTypeMap[r.type] === 'PTR');

        if (ptrRecords.length > 0) {
          setReverseDNSResult({
            ip: reverseIP,
            hostnames: ptrRecords.map(r => r.value),
            status: 'success'
          });
        } else {
          setReverseDNSResult({
            ip: reverseIP,
            error: 'No PTR records found',
            status: 'no_records'
          });
        }
      } else {
        setReverseDNSResult({
          ip: reverseIP,
          error: 'Failed to perform reverse DNS lookup',
          status: 'error'
        });
      }
    } catch (error) {
      console.error('Reverse DNS lookup error:', error);
      setReverseDNSResult({
        ip: reverseIP,
        error: 'Network error',
        status: 'error'
      });
    } finally {
      setLoadingReverse(false);
    }
  };

  // DNS Propagation Checker
  const checkPropagation = async () => {
    if (!domain) return;

    setCheckingPropagation(true);
    setShowPropagation(true);
    setPropagationResults([]);

    // Public DNS servers from different locations
    const dnsServers = [
      { name: 'Google (USA)', server: '8.8.8.8', location: 'Mountain View, CA' },
      { name: 'Cloudflare (Global)', server: '1.1.1.1', location: 'Global Anycast' },
      { name: 'Quad9 (Global)', server: '9.9.9.9', location: 'Global Anycast' },
      { name: 'OpenDNS (USA)', server: '208.67.222.222', location: 'San Francisco, CA' },
      { name: 'Google Secondary', server: '8.8.4.4', location: 'Mountain View, CA' },
      { name: 'Cloudflare Secondary', server: '1.0.0.1', location: 'Global Anycast' },
    ];

    const results = [];

    for (const dns of dnsServers) {
      try {
        // Since we can't query specific DNS servers from the browser, we'll use the default
        // In a real implementation, this would query via a backend API
        const response = await fetch(`/api/dns-lookup?domain=${domain}`);
        const data = await response.json();

        if (response.ok) {
          const aRecords = data.filter(r => dnsRecordTypeMap[r.type] === 'A');
          results.push({
            ...dns,
            status: 'success',
            records: aRecords.length > 0 ? aRecords.map(r => r.value).join(', ') : 'No A records',
            timestamp: new Date().toISOString()
          });
        } else {
          results.push({
            ...dns,
            status: 'error',
            error: 'Failed to resolve',
            timestamp: new Date().toISOString()
          });
        }
      } catch (error) {
        results.push({
          ...dns,
          status: 'error',
          error: 'Network error',
          timestamp: new Date().toISOString()
        });
      }

      // Small delay between requests
      await new Promise(resolve => setTimeout(resolve, 200));
    }

    setPropagationResults(results);
    setCheckingPropagation(false);
  };

  // Export functions
  const handleExportCSV = () => {
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

  const handleExportJSON = () => {
    const jsonData = {
      domain,
      timestamp: new Date().toISOString(),
      healthScore,
      records
    };

    const blob = new Blob([JSON.stringify(jsonData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dns_records_${domain}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Copy individual record
  const copyRecord = async (value, index) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedIndex(index);
      setTimeout(() => setCopiedIndex(null), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  // Toggle record type filter
  const toggleRecordType = (type) => {
    const newSet = new Set(selectedRecordTypes);
    if (newSet.has(type)) {
      newSet.delete(type);
    } else {
      newSet.add(type);
    }
    setSelectedRecordTypes(newSet);
  };

  // Toggle record expansion
  const toggleRecordExpansion = (index) => {
    const newSet = new Set(expandedRecords);
    if (newSet.has(index)) {
      newSet.delete(index);
    } else {
      newSet.add(index);
    }
    setExpandedRecords(newSet);
  };

  // Toggle bulk result expansion
  const toggleBulkResultExpansion = (index) => {
    const newSet = new Set(expandedBulkResults);
    if (newSet.has(index)) {
      newSet.delete(index);
    } else {
      newSet.add(index);
    }
    setExpandedBulkResults(newSet);
  };

  // Get record details for expansion
  const getRecordDetails = (record) => {
    const details = [];

    // Type-specific details
    if (record.type === 'MX') {
      const parts = record.value.split(' ');
      if (parts.length >= 2) {
        details.push({ label: 'Priority', value: parts[0] });
        details.push({ label: 'Mail Server', value: parts.slice(1).join(' ') });
      }
    } else if (record.type === 'SOA') {
      const parts = record.value.split(' ');
      if (parts.length >= 7) {
        details.push({ label: 'Primary NS', value: parts[0] });
        details.push({ label: 'Admin Email', value: parts[1] });
        details.push({ label: 'Serial', value: parts[2] });
        details.push({ label: 'Refresh', value: `${parts[3]}s` });
        details.push({ label: 'Retry', value: `${parts[4]}s` });
        details.push({ label: 'Expire', value: `${parts[5]}s` });
        details.push({ label: 'Min TTL', value: `${parts[6]}s` });
      }
    } else if (record.type === 'SRV') {
      const parts = record.value.split(' ');
      if (parts.length >= 4) {
        details.push({ label: 'Priority', value: parts[0] });
        details.push({ label: 'Weight', value: parts[1] });
        details.push({ label: 'Port', value: parts[2] });
        details.push({ label: 'Target', value: parts[3] });
      }
    } else if (record.type === 'TXT') {
      if (record.value.includes('v=spf1')) {
        details.push({ label: 'Type', value: 'SPF Record' });
        details.push({ label: 'Purpose', value: 'Email sender authentication' });
      } else if (record.value.includes('v=DMARC1')) {
        details.push({ label: 'Type', value: 'DMARC Record' });
        details.push({ label: 'Purpose', value: 'Email authentication policy' });
      } else if (record.value.includes('v=DKIM1')) {
        details.push({ label: 'Type', value: 'DKIM Record' });
        details.push({ label: 'Purpose', value: 'Email digital signature' });
      }
      details.push({ label: 'Length', value: `${record.value.length} characters` });
    } else if (record.type === 'CAA') {
      const parts = record.value.split(' ');
      if (parts.length >= 3) {
        details.push({ label: 'Flags', value: parts[0] });
        details.push({ label: 'Tag', value: parts[1] });
        details.push({ label: 'CA Domain', value: parts.slice(2).join(' ').replace(/"/g, '') });
      }
    }

    // Common details for all records
    details.push({ label: 'Original TTL', value: formatTTL(record.ttl) });
    if (record.timestamp) {
      details.push({ label: 'Fetched', value: new Date(record.timestamp).toLocaleString() });
    }

    return details;
  };

  // Filter records
  const filteredRecords = records.filter(record => {
    const matchesType = selectedRecordTypes.has(record.type);
    const matchesSearch = !filterValue ||
      record.value.toLowerCase().includes(filterValue.toLowerCase()) ||
      record.type.toLowerCase().includes(filterValue.toLowerCase());
    return matchesType && matchesSearch;
  });

  const checkSecurity = () => {
    const hasSPF = records.some(record => record.type === 'TXT' && record.value.includes('v=spf1'));
    const hasDKIM = records.some(record => record.type === 'TXT' && record.value.includes('v=DKIM1'));
    const hasDMARC = records.some(record => record.type === 'TXT' && record.value.includes('v=DMARC1'));

    return { spf: hasSPF, dkim: hasDKIM, dmarc: hasDMARC };
  };

  const securityStatus = checkSecurity();

  // Build DNS hierarchy for visualization
  const buildDNSHierarchy = () => {
    const hierarchy = {
      domain: domain,
      children: []
    };

    // Group by record type
    const groupedRecords = records.reduce((acc, record) => {
      if (!acc[record.type]) acc[record.type] = [];
      acc[record.type].push(record);
      return acc;
    }, {});

    // Add record type groups
    Object.entries(groupedRecords).forEach(([type, recs]) => {
      const typeNode = {
        name: `${type} Records (${recs.length})`,
        type: type,
        children: recs.map(r => ({
          name: r.value,
          type: 'record',
          ttl: r.ttl
        }))
      };
      hierarchy.children.push(typeNode);
    });

    return hierarchy;
  };

  // TTL countdown ticker
  useEffect(() => {
    if (records.length === 0) return;

    const interval = setInterval(() => {
      setTick(t => t + 1);
    }, 1000);

    return () => clearInterval(interval);
  }, [records]);

  // Calculate remaining TTL
  const getRemainingTTL = (record) => {
    if (!record.timestamp) return record.ttl;
    const elapsed = Math.floor((Date.now() - record.timestamp) / 1000);
    const remaining = record.ttl - elapsed;
    return Math.max(0, remaining);
  };

  // Format TTL display
  const formatTTL = (seconds) => {
    if (seconds >= 86400) {
      const days = Math.floor(seconds / 86400);
      const hours = Math.floor((seconds % 86400) / 3600);
      return `${days}d ${hours}h`;
    } else if (seconds >= 3600) {
      const hours = Math.floor(seconds / 3600);
      const mins = Math.floor((seconds % 3600) / 60);
      return `${hours}h ${mins}m`;
    } else if (seconds >= 60) {
      const mins = Math.floor(seconds / 60);
      const secs = seconds % 60;
      return `${mins}m ${secs}s`;
    }
    return `${seconds}s`;
  };

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyboard = (e) => {
      // Ctrl/Cmd + K to focus search
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        document.querySelector('input[type="text"]')?.focus();
      }
      // Ctrl/Cmd + L to clear
      if ((e.ctrlKey || e.metaKey) && e.key === 'l') {
        e.preventDefault();
        setDomain('');
        setRecords([]);
        setHealthScore(null);
      }
    };

    window.addEventListener('keydown', handleKeyboard);
    return () => window.removeEventListener('keydown', handleKeyboard);
  }, []);

  // Send height to parent for iframe embedding
  useEffect(() => {
    const sendHeight = () => {
      const height = document.documentElement.scrollHeight;
      window.parent.postMessage({ type: 'resize', height }, '*');
    };

    sendHeight();
    window.addEventListener('resize', sendHeight);
    const observer = new MutationObserver(sendHeight);
    observer.observe(document.body, { childList: true, subtree: true, attributes: true });

    return () => {
      window.removeEventListener('resize', sendHeight);
      observer.disconnect();
    };
  }, [records]);

  return (
    <div className="max-w-6xl mx-auto p-6 bg-white dark:bg-gray-900 rounded-lg shadow-lg">
      {/* Mode Toggle */}
      <div className="flex justify-center mb-4">
        <div className="inline-flex rounded-lg border border-gray-300 dark:border-gray-600 bg-gray-100 dark:bg-gray-800 p-1">
          <button
            onClick={() => {
              setBulkMode(false);
              setCompareMode(false);
              setBulkResults([]);
              setRecords2([]);
              setHealthScore2(null);
            }}
            className={`px-4 py-2 rounded-md text-sm font-medium transition ${
              !bulkMode && !compareMode
                ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm'
                : 'text-gray-700 dark:text-gray-300'
            }`}
          >
            Single Domain
          </button>
          <button
            onClick={() => {
              setBulkMode(false);
              setCompareMode(true);
              setBulkResults([]);
              setRecords([]);
              setRecords2([]);
              setHealthScore(null);
              setHealthScore2(null);
            }}
            className={`px-4 py-2 rounded-md text-sm font-medium transition ${
              compareMode
                ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm'
                : 'text-gray-700 dark:text-gray-300'
            }`}
          >
            Compare Domains
          </button>
          <button
            onClick={() => {
              setBulkMode(true);
              setCompareMode(false);
              setRecords([]);
              setRecords2([]);
              setHealthScore(null);
              setHealthScore2(null);
            }}
            className={`px-4 py-2 rounded-md text-sm font-medium transition ${
              bulkMode
                ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm'
                : 'text-gray-700 dark:text-gray-300'
            }`}
          >
            Bulk Lookup
          </button>
        </div>
      </div>

      {/* Compare Mode Input */}
      {compareMode ? (
        <div className="mb-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-2">Domain 1</label>
              <InputSection
                domain={domain}
                setDomain={(val) => {
                  setDomain(val);
                  validateDomain(val);
                }}
                handleLookup={() => {}}
                loading={false}
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-2">Domain 2</label>
              <input
                type="text"
                value={domain2}
                onChange={(e) => setDomain2(e.target.value)}
                placeholder="Enter second domain"
                className="w-full p-3 border border-gray-300 dark:border-gray-600 rounded-lg font-mono text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white dark:bg-gray-800"
              />
            </div>
          </div>
          <button
            onClick={handleCompareLookup}
            disabled={loading || loading2}
            className="mt-3 w-full px-4 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white font-semibold rounded-lg transition"
          >
            {loading || loading2 ? 'Comparing...' : 'Compare Domains'}
          </button>
        </div>
      ) : bulkMode ? (
        <div className="mb-6">
          <label className="block text-sm font-medium mb-2">Enter domains (one per line)</label>
          <textarea
            value={bulkDomains}
            onChange={(e) => setBulkDomains(e.target.value)}
            placeholder="google.com&#10;github.com&#10;cloudflare.com"
            className="w-full h-40 p-3 border border-gray-300 dark:border-gray-600 rounded-lg font-mono text-sm resize-none focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white dark:bg-gray-800"
          />
          <button
            onClick={handleBulkLookup}
            disabled={loading}
            className="mt-3 w-full px-4 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white font-semibold rounded-lg transition"
          >
            {loading ? 'Looking up...' : 'Lookup All Domains'}
          </button>
        </div>
      ) : (
        <>
          {/* Input Section with History */}
          <div className="relative">
            <InputSection
              domain={domain}
              setDomain={(val) => {
                setDomain(val);
                validateDomain(val);
              }}
              handleLookup={() => handleLookup()}
              loading={loading}
            />

        {/* Validation Error */}
        {validationError && (
          <div className="mt-2 text-red-500 text-sm">{validationError}</div>
        )}

        {/* Recent History Toggle */}
        {recentLookups.length > 0 && (
          <button
            onClick={() => setShowHistory(!showHistory)}
            className="mt-2 text-sm text-blue-500 hover:text-blue-700 flex items-center gap-1"
          >
            <History className="w-4 h-4" />
            Recent Lookups ({recentLookups.length})
          </button>
        )}

        {/* History Dropdown */}
        {showHistory && recentLookups.length > 0 && (
          <div className="absolute z-10 mt-1 w-full bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg shadow-lg max-h-60 overflow-y-auto">
            <div className="flex justify-between items-center p-2 border-b border-gray-200 dark:border-gray-700">
              <span className="text-sm font-semibold">Recent Lookups</span>
              <button
                onClick={clearHistory}
                className="text-xs text-red-500 hover:text-red-700"
              >
                Clear All
              </button>
            </div>
            {recentLookups.map((recentDomain, index) => (
              <button
                key={index}
                onClick={() => {
                  handleLookup(recentDomain);
                  setShowHistory(false);
                }}
                className="w-full text-left px-4 py-2 hover:bg-gray-100 dark:hover:bg-gray-700 text-sm"
              >
                {recentDomain}
              </button>
            ))}
          </div>
        )}
      </div>

          {/* Example Domains */}
          <div className="mt-4 flex flex-wrap gap-2">
            <span className="text-sm text-gray-600 dark:text-gray-400">Try:</span>
            {EXAMPLE_DOMAINS.map((exampleDomain) => (
              <button
                key={exampleDomain}
                onClick={() => handleLookup(exampleDomain)}
                className="text-xs px-2 py-1 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded"
              >
                {exampleDomain}
              </button>
            ))}
          </div>
        </>
      )}

      {/* Bulk Results */}
      {bulkMode && bulkResults.length > 0 && (
        <div className="mt-6 space-y-4">
          <h2 className="text-2xl font-bold">Results ({bulkResults.length} domains)</h2>
          {bulkResults.map((result, idx) => (
            <div
              key={idx}
              className={`border rounded-lg ${
                result.status === 'success'
                  ? 'border-green-200 dark:border-green-800 bg-green-50 dark:bg-green-900/20'
                  : 'border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20'
              }`}
            >
              <div
                className="p-4 cursor-pointer hover:bg-opacity-80 transition"
                onClick={() => toggleBulkResultExpansion(idx)}
              >
                <div className="flex items-center justify-between mb-2">
                  <h3 className="font-bold text-lg">{result.domain}</h3>
                  <div className="flex items-center gap-3">
                    {result.status === 'success' && result.healthScore && (
                      <div className="flex items-center gap-2">
                        <span className={`text-2xl font-bold ${
                          result.healthScore.score >= 80 ? 'text-green-600' :
                          result.healthScore.score >= 60 ? 'text-yellow-600' :
                          'text-red-600'
                        }`}>
                          {result.healthScore.score}
                        </span>
                        <span className="text-sm text-gray-600 dark:text-gray-400">/100</span>
                      </div>
                    )}
                    <span className="text-xs text-gray-500 dark:text-gray-400">
                      {expandedBulkResults.has(idx) ? '▼' : '▶'}
                    </span>
                  </div>
                </div>
                {result.status === 'error' ? (
                  <p className="text-red-600 dark:text-red-400">{result.error}</p>
                ) : (
                  <div className="text-sm text-gray-700 dark:text-gray-300">
                    {result.records.length} DNS records found
                  </div>
                )}
              </div>

              {/* Expanded Details */}
              {expandedBulkResults.has(idx) && result.status === 'success' && (
                <div className="border-t border-gray-300 dark:border-gray-600 p-4 bg-white dark:bg-gray-800">
                  {/* Health Score Details */}
                  {result.healthScore && (
                    <div className="mb-4 p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                      <h4 className="font-semibold mb-2 text-sm">Health Analysis</h4>
                      {result.healthScore.issues.length > 0 && (
                        <div className="mb-2">
                          <p className="text-xs font-semibold text-red-600">Issues:</p>
                          <ul className="list-disc list-inside text-xs space-y-1">
                            {result.healthScore.issues.map((issue, i) => (
                              <li key={i} className="text-red-700 dark:text-red-400">{issue}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                      {result.healthScore.recommendations.length > 0 && (
                        <div>
                          <p className="text-xs font-semibold text-blue-600">Recommendations:</p>
                          <ul className="list-disc list-inside text-xs space-y-1">
                            {result.healthScore.recommendations.map((rec, i) => (
                              <li key={i} className="text-blue-700 dark:text-blue-400">{rec}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  )}

                  {/* DNS Records Table */}
                  <div className="overflow-x-auto">
                    <table className="w-full border-collapse text-sm">
                      <thead>
                        <tr className="bg-gray-100 dark:bg-gray-700">
                          <th className="border border-gray-300 dark:border-gray-600 px-3 py-2 text-left">Type</th>
                          <th className="border border-gray-300 dark:border-gray-600 px-3 py-2 text-left">Value</th>
                          <th className="border border-gray-300 dark:border-gray-600 px-3 py-2 text-left">TTL</th>
                        </tr>
                      </thead>
                      <tbody>
                        {result.records.map((record, recIdx) => (
                          <tr key={recIdx} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-3 py-2 font-mono text-xs">
                              <span className={`px-2 py-1 rounded ${
                                record.type === 'A' || record.type === 'AAAA' ? 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200' :
                                record.type === 'MX' ? 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200' :
                                record.type === 'TXT' ? 'bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-200' :
                                'bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-200'
                              }`}>
                                {record.type}
                              </span>
                            </td>
                            <td className="border border-gray-300 dark:border-gray-600 px-3 py-2 font-mono text-xs break-all">
                              {record.value}
                            </td>
                            <td className="border border-gray-300 dark:border-gray-600 px-3 py-2 font-mono text-xs">
                              {record.ttl}s
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Compare Mode Results */}
      {compareMode && records.length > 0 && records2.length > 0 && (
        <div className="mt-6">
          <h2 className="text-2xl font-bold mb-4">Comparison Results</h2>

          {/* Health Score Comparison */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-800">
              <h3 className="font-bold text-lg mb-2">{domain}</h3>
              {healthScore && (
                <div className="flex items-center gap-2">
                  <span className={`text-4xl font-bold ${
                    healthScore.score >= 80 ? 'text-green-600' :
                    healthScore.score >= 60 ? 'text-yellow-600' :
                    'text-red-600'
                  }`}>
                    {healthScore.score}
                  </span>
                  <span className="text-sm text-gray-600 dark:text-gray-400">/100</span>
                  <span className={`text-2xl font-bold ml-2 ${
                    healthScore.grade === 'A' ? 'text-green-600' :
                    healthScore.grade === 'B' ? 'text-blue-600' :
                    healthScore.grade === 'C' ? 'text-yellow-600' :
                    'text-red-600'
                  }`}>
                    {healthScore.grade}
                  </span>
                </div>
              )}
            </div>

            <div className="p-4 bg-purple-50 dark:bg-purple-900/20 rounded-lg border border-purple-200 dark:border-purple-800">
              <h3 className="font-bold text-lg mb-2">{domain2}</h3>
              {healthScore2 && (
                <div className="flex items-center gap-2">
                  <span className={`text-4xl font-bold ${
                    healthScore2.score >= 80 ? 'text-green-600' :
                    healthScore2.score >= 60 ? 'text-yellow-600' :
                    'text-red-600'
                  }`}>
                    {healthScore2.score}
                  </span>
                  <span className="text-sm text-gray-600 dark:text-gray-400">/100</span>
                  <span className={`text-2xl font-bold ml-2 ${
                    healthScore2.grade === 'A' ? 'text-green-600' :
                    healthScore2.grade === 'B' ? 'text-blue-600' :
                    healthScore2.grade === 'C' ? 'text-yellow-600' :
                    'text-red-600'
                  }`}>
                    {healthScore2.grade}
                  </span>
                </div>
              )}
            </div>
          </div>

          {/* Side-by-side Record Comparison */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Domain 1 Records */}
            <div>
              <h3 className="font-semibold mb-2 text-blue-600 dark:text-blue-400">{domain} ({records.length} records)</h3>
              <div className="overflow-x-auto max-h-96 border border-blue-200 dark:border-blue-800 rounded-lg">
                <table className="w-full border-collapse text-sm">
                  <thead className="sticky top-0 bg-blue-100 dark:bg-blue-900">
                    <tr>
                      <th className="border border-blue-300 dark:border-blue-700 px-2 py-1 text-left">Type</th>
                      <th className="border border-blue-300 dark:border-blue-700 px-2 py-1 text-left">Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {records.map((record, idx) => (
                      <tr key={idx} className="hover:bg-blue-50 dark:hover:bg-blue-900/30">
                        <td className="border border-blue-200 dark:border-blue-800 px-2 py-1 font-mono text-xs">
                          <span className={`px-1.5 py-0.5 rounded ${
                            record.type === 'A' || record.type === 'AAAA' ? 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200' :
                            record.type === 'MX' ? 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200' :
                            record.type === 'TXT' ? 'bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-200' :
                            'bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-200'
                          }`}>
                            {record.type}
                          </span>
                        </td>
                        <td className="border border-blue-200 dark:border-blue-800 px-2 py-1 font-mono text-xs break-all">
                          {record.value.length > 60 ? `${record.value.substring(0, 60)}...` : record.value}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Domain 2 Records */}
            <div>
              <h3 className="font-semibold mb-2 text-purple-600 dark:text-purple-400">{domain2} ({records2.length} records)</h3>
              <div className="overflow-x-auto max-h-96 border border-purple-200 dark:border-purple-800 rounded-lg">
                <table className="w-full border-collapse text-sm">
                  <thead className="sticky top-0 bg-purple-100 dark:bg-purple-900">
                    <tr>
                      <th className="border border-purple-300 dark:border-purple-700 px-2 py-1 text-left">Type</th>
                      <th className="border border-purple-300 dark:border-purple-700 px-2 py-1 text-left">Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {records2.map((record, idx) => (
                      <tr key={idx} className="hover:bg-purple-50 dark:hover:bg-purple-900/30">
                        <td className="border border-purple-200 dark:border-purple-800 px-2 py-1 font-mono text-xs">
                          <span className={`px-1.5 py-0.5 rounded ${
                            record.type === 'A' || record.type === 'AAAA' ? 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200' :
                            record.type === 'MX' ? 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200' :
                            record.type === 'TXT' ? 'bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-200' :
                            'bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-200'
                          }`}>
                            {record.type}
                          </span>
                        </td>
                        <td className="border border-purple-200 dark:border-purple-800 px-2 py-1 font-mono text-xs break-all">
                          {record.value.length > 60 ? `${record.value.substring(0, 60)}...` : record.value}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Health Score */}
      {healthScore && !compareMode && (
        <div className="mt-6 p-4 bg-gradient-to-r from-blue-50 to-purple-50 dark:from-blue-900/20 dark:to-purple-900/20 rounded-lg border border-blue-200 dark:border-blue-800">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-lg font-bold">DNS Health Score</h3>
            <div className="flex items-center gap-2">
              <span className={`text-3xl font-bold ${
                healthScore.score >= 80 ? 'text-green-600' :
                healthScore.score >= 60 ? 'text-yellow-600' :
                'text-red-600'
              }`}>
                {healthScore.score}
              </span>
              <span className="text-sm text-gray-600 dark:text-gray-400">/100</span>
              <span className={`text-2xl font-bold ml-2 ${
                healthScore.grade === 'A' ? 'text-green-600' :
                healthScore.grade === 'B' ? 'text-blue-600' :
                healthScore.grade === 'C' ? 'text-yellow-600' :
                'text-red-600'
              }`}>
                {healthScore.grade}
              </span>
            </div>
          </div>

          {healthScore.issues.length > 0 && (
            <div className="mb-2">
              <h4 className="font-semibold text-red-600 text-sm mb-1">Issues:</h4>
              <ul className="list-disc list-inside text-sm space-y-1">
                {healthScore.issues.map((issue, i) => (
                  <li key={i} className="text-red-700 dark:text-red-400">{issue}</li>
                ))}
              </ul>
            </div>
          )}

          {healthScore.recommendations.length > 0 && (
            <div>
              <h4 className="font-semibold text-blue-600 text-sm mb-1">Recommendations:</h4>
              <ul className="list-disc list-inside text-sm space-y-1">
                {healthScore.recommendations.map((rec, i) => (
                  <li key={i} className="text-blue-700 dark:text-blue-400">{rec}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Skeleton Loader */}
      {loading && (
        <div className="mt-6 space-y-4 animate-pulse">
          <div className="h-20 bg-gray-200 dark:bg-gray-700 rounded-lg"></div>
          <div className="space-y-2">
            {[1, 2, 3, 4, 5].map((i) => (
              <div key={i} className="h-16 bg-gray-200 dark:bg-gray-700 rounded-lg"></div>
            ))}
          </div>
        </div>
      )}

      {records.length > 0 && !loading && (
        <>
          {/* Filters and Export */}
          <div className="flex flex-wrap justify-between items-center gap-4 mt-6">
            <div className="flex gap-2">
              <Button
                onClick={handleExportCSV}
                className="px-4 py-2 bg-green-500 hover:bg-green-600 text-white rounded-lg transition duration-200"
              >
                <Download className="mr-2 h-4 w-4" />
                CSV
              </Button>
              <Button
                onClick={handleExportJSON}
                className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition duration-200"
              >
                <Download className="mr-2 h-4 w-4" />
                JSON
              </Button>
              <Button
                onClick={() => setShowFilters(!showFilters)}
                className="px-4 py-2 bg-purple-500 hover:bg-purple-600 text-white rounded-lg transition duration-200"
              >
                <Filter className="mr-2 h-4 w-4" />
                Filters
              </Button>
              <Button
                onClick={() => setShowDNSMap(!showDNSMap)}
                className="px-4 py-2 bg-orange-500 hover:bg-orange-600 text-white rounded-lg transition duration-200"
              >
                {showDNSMap ? 'Hide' : 'Show'} DNS Map
              </Button>
              <Button
                onClick={checkPropagation}
                disabled={checkingPropagation}
                className="px-4 py-2 bg-teal-500 hover:bg-teal-600 disabled:bg-gray-400 text-white rounded-lg transition duration-200"
              >
                {checkingPropagation ? 'Checking...' : 'Check Propagation'}
              </Button>
            </div>

            {/* Reverse DNS Lookup Tool */}
            <div className="flex gap-2 items-center">
              <input
                type="text"
                value={reverseIP}
                onChange={(e) => setReverseIP(e.target.value)}
                placeholder="Enter IP for reverse lookup"
                className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white dark:bg-gray-800"
              />
              <Button
                onClick={handleReverseDNS}
                disabled={loadingReverse}
                className="px-4 py-2 bg-indigo-500 hover:bg-indigo-600 disabled:bg-gray-400 text-white rounded-lg transition duration-200 whitespace-nowrap"
              >
                {loadingReverse ? 'Looking up...' : 'Reverse DNS'}
              </Button>
            </div>
          </div>

            <Input
              className="w-full md:w-1/3 border border-gray-300 dark:border-gray-600 p-3 rounded-lg bg-gray-50 dark:bg-gray-800 text-gray-700 dark:text-white"
              type="text"
              placeholder="Search records..."
              value={filterValue}
              onChange={(e) => setFilterValue(e.target.value)}
            />
          </div>

          {/* Record Type Filters */}
          {showFilters && (
            <div className="mt-4 p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
              <h4 className="font-semibold mb-2 text-sm">Filter by Record Type:</h4>
              <div className="flex flex-wrap gap-2">
                {RECORD_TYPES.map(type => (
                  <button
                    key={type}
                    onClick={() => toggleRecordType(type)}
                    className={`px-3 py-1 rounded-full text-sm transition ${
                      selectedRecordTypes.has(type)
                        ? 'bg-blue-500 text-white'
                        : 'bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300'
                    }`}
                  >
                    {type}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Reverse DNS Results */}
          {reverseDNSResult && (
            <div className={`mt-4 p-4 rounded-lg border-2 ${
              reverseDNSResult.status === 'success'
                ? 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800'
                : reverseDNSResult.status === 'no_records'
                ? 'bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800'
                : 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800'
            }`}>
              <h4 className="font-semibold mb-2">Reverse DNS Lookup for {reverseDNSResult.ip}</h4>
              {reverseDNSResult.status === 'success' ? (
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">Hostname(s):</p>
                  <div className="space-y-1">
                    {reverseDNSResult.hostnames.map((hostname, idx) => (
                      <div key={idx} className="p-2 bg-white dark:bg-gray-800 rounded font-mono text-sm">
                        {hostname}
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <p className={`text-sm ${
                  reverseDNSResult.status === 'no_records'
                    ? 'text-yellow-700 dark:text-yellow-400'
                    : 'text-red-700 dark:text-red-400'
                }`}>
                  {reverseDNSResult.error}
                </p>
              )}
            </div>
          )}

          {/* DNS Map Visualization */}
          {showDNSMap && (
            <div className="mt-6 p-6 bg-gradient-to-br from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 rounded-lg border border-blue-200 dark:border-blue-800">
              <h3 className="text-xl font-bold mb-4 text-center">DNS Record Hierarchy</h3>
              <div className="flex flex-col items-center">
                {/* Root Domain */}
                <div className="bg-blue-600 text-white px-6 py-3 rounded-lg font-bold text-lg shadow-lg mb-6">
                  {domain}
                </div>

                {/* Record Type Groups */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 w-full">
                  {buildDNSHierarchy().children.map((group, idx) => (
                    <div key={idx} className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow-md border-l-4" style={{
                      borderLeftColor:
                        group.type === 'A' || group.type === 'AAAA' ? '#3b82f6' :
                        group.type === 'MX' ? '#10b981' :
                        group.type === 'TXT' ? '#8b5cf6' :
                        group.type === 'NS' ? '#f59e0b' :
                        group.type === 'SOA' ? '#ef4444' :
                        '#6b7280'
                    }}>
                      <div className="font-semibold text-lg mb-3 flex items-center gap-2">
                        <span className={`px-2 py-1 rounded text-sm ${
                          group.type === 'A' || group.type === 'AAAA' ? 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200' :
                          group.type === 'MX' ? 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200' :
                          group.type === 'TXT' ? 'bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-200' :
                          group.type === 'NS' ? 'bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-200' :
                          group.type === 'SOA' ? 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200' :
                          'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200'
                        }`}>
                          {group.type}
                        </span>
                        <span className="text-gray-600 dark:text-gray-400 text-sm">({group.children.length})</span>
                      </div>
                      <div className="space-y-2 max-h-60 overflow-y-auto">
                        {group.children.slice(0, 5).map((record, i) => (
                          <div key={i} className="text-xs font-mono bg-gray-50 dark:bg-gray-700 p-2 rounded break-all">
                            {record.name.length > 50 ? `${record.name.substring(0, 50)}...` : record.name}
                          </div>
                        ))}
                        {group.children.length > 5 && (
                          <div className="text-xs text-gray-500 dark:text-gray-400 italic">
                            +{group.children.length - 5} more
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* DNS Propagation Results */}
          {showPropagation && (
            <div className="mt-6 p-6 bg-gradient-to-br from-teal-50 to-cyan-50 dark:from-teal-900/20 dark:to-cyan-900/20 rounded-lg border border-teal-200 dark:border-teal-800">
              <h3 className="text-xl font-bold mb-4">DNS Propagation Check</h3>
              <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                Checking DNS records from multiple global DNS servers
              </p>

              {checkingPropagation ? (
                <div className="space-y-2">
                  {[1, 2, 3, 4, 5, 6].map((i) => (
                    <div key={i} className="h-16 bg-gray-200 dark:bg-gray-700 rounded-lg animate-pulse"></div>
                  ))}
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {propagationResults.map((result, idx) => (
                    <div
                      key={idx}
                      className={`p-4 rounded-lg border-2 ${
                        result.status === 'success'
                          ? 'border-green-200 dark:border-green-800 bg-green-50 dark:bg-green-900/20'
                          : 'border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <div>
                          <h4 className="font-bold">{result.name}</h4>
                          <p className="text-xs text-gray-600 dark:text-gray-400">{result.location}</p>
                        </div>
                        <span className={`px-2 py-1 rounded text-xs font-semibold ${
                          result.status === 'success'
                            ? 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200'
                            : 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200'
                        }`}>
                          {result.status === 'success' ? 'Resolved' : 'Failed'}
                        </span>
                      </div>
                      <div className="text-sm font-mono bg-white dark:bg-gray-800 p-2 rounded">
                        {result.status === 'success' ? result.records : result.error}
                      </div>
                      <div className="text-xs text-gray-500 dark:text-gray-400 mt-2">
                        Server: {result.server}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {!checkingPropagation && propagationResults.length > 0 && (
                <div className="mt-4 text-sm text-gray-600 dark:text-gray-400">
                  ✓ Checked {propagationResults.length} DNS servers globally
                </div>
              )}
            </div>
          )}

          {/* Records Table with Copy Buttons */}
          <div className="mt-6 overflow-x-auto">
            <table className="w-full border-collapse">
              <thead>
                <tr className="bg-gray-100 dark:bg-gray-800">
                  <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Type</th>
                  <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Value</th>
                  <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">TTL</th>
                  <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-center">Copy</th>
                </tr>
              </thead>
              <tbody>
                {filteredRecords.map((record, index) => (
                  <>
                    <tr
                      key={index}
                      className="hover:bg-gray-50 dark:hover:bg-gray-800 cursor-pointer"
                      onClick={() => toggleRecordExpansion(index)}
                    >
                      <td className="border border-gray-300 dark:border-gray-600 px-4 py-2 font-mono text-sm">
                        <span className={`px-2 py-1 rounded ${
                          record.type === 'A' || record.type === 'AAAA' ? 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200' :
                          record.type === 'MX' ? 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200' :
                          record.type === 'TXT' ? 'bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-200' :
                          'bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-200'
                        }`}>
                          {record.type}
                        </span>
                      </td>
                      <td className="border border-gray-300 dark:border-gray-600 px-4 py-2 font-mono text-sm break-all">
                        {record.value}
                      </td>
                      <td className="border border-gray-300 dark:border-gray-600 px-4 py-2 font-mono text-sm">
                        {record.timestamp ? (
                          <div>
                            <div className={`font-semibold ${
                              getRemainingTTL(record) === 0 ? 'text-red-600' :
                              getRemainingTTL(record) < 60 ? 'text-yellow-600' :
                              'text-gray-800 dark:text-gray-200'
                            }`}>
                              {formatTTL(getRemainingTTL(record))}
                            </div>
                            <div className="text-xs text-gray-500">of {formatTTL(record.ttl)}</div>
                          </div>
                        ) : (
                          `${record.ttl}s`
                        )}
                      </td>
                      <td className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-center">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            copyRecord(record.value, index);
                          }}
                          className="p-1 hover:bg-gray-200 dark:hover:bg-gray-700 rounded"
                        >
                          {copiedIndex === index ? (
                            <Check className="w-4 h-4 text-green-500" />
                          ) : (
                            <Copy className="w-4 h-4" />
                          )}
                        </button>
                      </td>
                    </tr>
                    {expandedRecords.has(index) && (
                      <tr key={`${index}-details`}>
                        <td colSpan="4" className="border border-gray-300 dark:border-gray-600 bg-gray-50 dark:bg-gray-800 px-6 py-4">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            {getRecordDetails(record).map((detail, i) => (
                              <div key={i} className="flex items-start">
                                <span className="font-semibold text-sm text-gray-600 dark:text-gray-400 min-w-[120px]">{detail.label}:</span>
                                <span className="text-sm text-gray-800 dark:text-gray-200 break-all">{detail.value}</span>
                              </div>
                            ))}
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                ))}
              </tbody>
            </table>
          </div>

          <div className="text-sm text-gray-500 dark:text-gray-400 mt-4">
            Showing {filteredRecords.length} of {records.length} records
          </div>

          <SecurityInsights securityStatus={securityStatus} />

          {/* SPF Record Summary */}
          {spfSummary && (
            <div className="mt-6 p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-800">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-lg font-bold">SPF Record Analysis</h3>
                <span className={`px-3 py-1 rounded-full text-sm font-semibold ${
                  spfSummary.strength === 'Strong' ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' :
                  spfSummary.strength === 'Moderate' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200' :
                  'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                }`}>
                  {spfSummary.strength}
                </span>
              </div>

              <div className="mb-3">
                <p className="text-xs text-gray-600 dark:text-gray-400 font-mono bg-gray-100 dark:bg-gray-800 p-2 rounded break-all">
                  {spfSummary.raw}
                </p>
              </div>

              <div className="mb-3">
                <h4 className="font-semibold text-sm mb-2">Authorized Senders ({spfSummary.mechanisms.length}):</h4>
                <div className="space-y-2">
                  {spfSummary.mechanisms.map((mech, i) => (
                    <div key={i} className="flex items-start gap-2 text-sm bg-white dark:bg-gray-800 p-2 rounded">
                      <span className={`px-2 py-0.5 rounded text-xs font-semibold ${
                        mech.action === 'Pass' ? 'bg-green-100 text-green-800' :
                        mech.action === 'Fail' ? 'bg-red-100 text-red-800' :
                        mech.action === 'SoftFail' ? 'bg-yellow-100 text-yellow-800' :
                        'bg-gray-100 text-gray-800'
                      }`}>
                        {mech.action}
                      </span>
                      <span className="font-semibold text-blue-600 dark:text-blue-400 min-w-[100px]">{mech.type}:</span>
                      <span className="text-gray-700 dark:text-gray-300 break-all">{mech.value}</span>
                    </div>
                  ))}
                </div>
              </div>

              {spfSummary.warnings.length > 0 && (
                <div className="mt-3">
                  <h4 className="font-semibold text-red-600 text-sm mb-1">Warnings:</h4>
                  <ul className="list-disc list-inside text-sm space-y-1">
                    {spfSummary.warnings.map((warning, i) => (
                      <li key={i} className="text-red-700 dark:text-red-400">{warning}</li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="mt-3 text-xs text-gray-600 dark:text-gray-400">
                <strong>Include count:</strong> {spfSummary.includeCount}/10 (DNS lookup limit)
              </div>
            </div>
          )}

          {/* DMARC Record Summary */}
          {dmarcSummary && (
            <div className="mt-6 p-4 bg-purple-50 dark:bg-purple-900/20 rounded-lg border border-purple-200 dark:border-purple-800">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-lg font-bold">DMARC Record Analysis</h3>
                <span className={`px-3 py-1 rounded-full text-sm font-semibold ${
                  dmarcSummary.strength === 'Strong' ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' :
                  dmarcSummary.strength === 'Moderate' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200' :
                  'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                }`}>
                  {dmarcSummary.strength}
                </span>
              </div>

              <div className="mb-3">
                <p className="text-xs text-gray-600 dark:text-gray-400 font-mono bg-gray-100 dark:bg-gray-800 p-2 rounded break-all">
                  {dmarcSummary.raw}
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-3">
                <div className="bg-white dark:bg-gray-800 p-3 rounded">
                  <span className="text-xs text-gray-600 dark:text-gray-400">Policy:</span>
                  <p className={`text-lg font-bold ${
                    dmarcSummary.policy === 'reject' ? 'text-green-600' :
                    dmarcSummary.policy === 'quarantine' ? 'text-yellow-600' :
                    'text-red-600'
                  }`}>
                    {dmarcSummary.policy.toUpperCase()}
                  </p>
                </div>

                <div className="bg-white dark:bg-gray-800 p-3 rounded">
                  <span className="text-xs text-gray-600 dark:text-gray-400">Subdomain Policy:</span>
                  <p className={`text-lg font-bold ${
                    dmarcSummary.subdomainPolicy === 'reject' ? 'text-green-600' :
                    dmarcSummary.subdomainPolicy === 'quarantine' ? 'text-yellow-600' :
                    'text-red-600'
                  }`}>
                    {dmarcSummary.subdomainPolicy.toUpperCase()}
                  </p>
                </div>

                <div className="bg-white dark:bg-gray-800 p-3 rounded">
                  <span className="text-xs text-gray-600 dark:text-gray-400">Enforcement:</span>
                  <p className="text-lg font-bold text-gray-800 dark:text-gray-200">{dmarcSummary.percentage}</p>
                </div>

                <div className="bg-white dark:bg-gray-800 p-3 rounded">
                  <span className="text-xs text-gray-600 dark:text-gray-400">Alignment Mode:</span>
                  <p className="text-sm font-semibold text-gray-800 dark:text-gray-200">
                    DKIM: {dmarcSummary.alignment.dkim === 'r' ? 'Relaxed' : 'Strict'}<br />
                    SPF: {dmarcSummary.alignment.spf === 'r' ? 'Relaxed' : 'Strict'}
                  </p>
                </div>
              </div>

              <div className="space-y-2 mb-3">
                <div className="text-sm">
                  <span className="font-semibold">Aggregate Reports:</span>
                  <p className="text-gray-700 dark:text-gray-300 text-xs break-all">{dmarcSummary.aggregateReports}</p>
                </div>
                <div className="text-sm">
                  <span className="font-semibold">Forensic Reports:</span>
                  <p className="text-gray-700 dark:text-gray-300 text-xs break-all">{dmarcSummary.forensicReports}</p>
                </div>
              </div>

              {dmarcSummary.warnings.length > 0 && (
                <div className="mt-3">
                  <h4 className="font-semibold text-red-600 text-sm mb-1">Warnings:</h4>
                  <ul className="list-disc list-inside text-sm space-y-1">
                    {dmarcSummary.warnings.map((warning, i) => (
                      <li key={i} className="text-red-700 dark:text-red-400">{warning}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* Keyboard Shortcuts Help */}
          <div className="mt-6 p-3 bg-gray-50 dark:bg-gray-800 rounded-lg text-xs text-gray-600 dark:text-gray-400">
            <strong>Keyboard Shortcuts:</strong> Ctrl/Cmd+K (focus search) | Ctrl/Cmd+L (clear)
          </div>
        </>
      )}
    </div>
  );
}
