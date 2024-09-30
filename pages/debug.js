"use client"

import { useState } from 'react'
import { Button } from "@nextui-org/button"
import { Input } from "@nextui-org/input"

export default function DebugPage() {
  const [domain, setDomain] = useState('')
  const [rawData, setRawData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const handleDebugLookup = async () => {
    if (!domain) return

    setLoading(true)
    setError(null)
    setRawData(null) // Clear previous results

    try {
      const response = await fetch(`/api/dns-lookup?domain=${domain}`)
      const data = await response.json()

      if (response.ok) {
        setRawData(data) // Store the raw API response
      } else {
        setError(`Error fetching DNS records: ${data.error}`)
      }
    } catch (error) {
      setError(`Error: ${error.message}`)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="max-w-4xl mx-auto p-6 bg-white dark:bg-gray-900 rounded-lg shadow-lg">
      <h1 className="text-4xl font-bold text-gray-800 dark:text-white mb-6 text-center">Debug DNS API</h1>
      
      <div className="flex flex-col md:flex-row items-center space-y-4 md:space-y-0 md:space-x-4">
        <Input
          className="w-full md:w-1/2 border border-gray-300 dark:border-gray-600 p-3 rounded-lg bg-gray-50 dark:bg-gray-800 text-gray-700 dark:text-white"
          type="text"
          placeholder="Enter domain name"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
        />
        <Button
          onClick={handleDebugLookup}
          disabled={loading}
          className="px-6 py-3 text-white bg-blue-500 hover:bg-blue-600 rounded-lg transition duration-200"
        >
          {loading ? "Loading..." : "Get Raw API Output"}
        </Button>
      </div>

      {error && (
        <div className="mt-4 p-4 bg-red-100 text-red-800 rounded-lg">
          {error}
        </div>
      )}

      {rawData && (
        <div className="mt-6 p-4 bg-gray-100 dark:bg-gray-800 text-sm overflow-x-auto rounded-lg">
          <pre className="whitespace-pre-wrap break-words text-gray-800 dark:text-gray-200">
            {JSON.stringify(rawData, null, 2)} {/* Pretty-print the JSON output */}
          </pre>
        </div>
      )}
    </div>
  )
}
