// components/InputSection.js
import { Button } from "@nextui-org/button"
import { Input } from "@nextui-org/input"
import { RefreshCw } from 'lucide-react';

const InputSection = ({ domain, setDomain, handleLookup, loading }) => (
  <div className="flex flex-col md:flex-row items-center space-y-4 md:space-y-0 md:space-x-4">
    <Input
      className="w-full md:w-1/2 border border-gray-300 dark:border-gray-600 p-3 rounded-lg bg-gray-50 dark:bg-gray-800 text-gray-700 dark:text-white"
      type="text"
      placeholder="Enter domain name"
      value={domain}
      onChange={(e) => setDomain(e.target.value)}
    />
    <Button
      onClick={handleLookup}
      disabled={loading}
      className="px-6 py-3 text-white bg-blue-500 hover:bg-blue-600 rounded-lg transition duration-200"
    >
      {loading ? <RefreshCw className="mr-2 h-5 w-5 animate-spin" /> : 'Lookup'}
    </Button>
  </div>
);

export default InputSection;
