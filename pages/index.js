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
          ttl: record.ttl
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
      <h1 className="text-4xl font-bold text-gray-800 dark:text-white mb-6 text-center">DNS Lookup Tool</h1>

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

      {/* Health Score */}
      {healthScore && (
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

      {records.length > 0 && (
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
                  <tr key={index} className="hover:bg-gray-50 dark:hover:bg-gray-800">
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
                      {record.ttl}s
                    </td>
                    <td className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-center">
                      <button
                        onClick={() => copyRecord(record.value, index)}
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
                ))}
              </tbody>
            </table>
          </div>

          <div className="text-sm text-gray-500 dark:text-gray-400 mt-4">
            Showing {filteredRecords.length} of {records.length} records
          </div>

          <SecurityInsights securityStatus={securityStatus} />

          {/* Keyboard Shortcuts Help */}
          <div className="mt-6 p-3 bg-gray-50 dark:bg-gray-800 rounded-lg text-xs text-gray-600 dark:text-gray-400">
            <strong>Keyboard Shortcuts:</strong> Ctrl/Cmd+K (focus search) | Ctrl/Cmd+L (clear)
          </div>
        </>
      )}
    </div>
  );
}
