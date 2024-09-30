// components/SecurityInsights.js
import { CheckCircle, XCircle } from 'lucide-react';

const SecurityInsights = ({ securityStatus }) => (
  <div className="bg-yellow-100 dark:bg-yellow-700 border-l-4 border-yellow-500 text-yellow-700 dark:text-yellow-200 p-4 mt-6 rounded-lg" role="alert">
    <p className="font-bold mb-2">Security Insights:</p>
    <div className="flex items-center space-x-2">
      <span>SPF Record:</span>
      {securityStatus.spf ? <CheckCircle className="text-green-500 h-5 w-5" /> : <XCircle className="text-red-500 h-5 w-5" />}
    </div>
    <div className="flex items-center space-x-2 mt-2">
      <span>DKIM Record:</span>
      {securityStatus.dkim ? <CheckCircle className="text-green-500 h-5 w-5" /> : <XCircle className="text-red-500 h-5 w-5" />}
    </div>
    <div className="flex items-center space-x-2 mt-2">
      <span>DMARC Record:</span>
      {securityStatus.dmarc ? <CheckCircle className="text-green-500 h-5 w-5" /> : <XCircle className="text-red-500 h-5 w-5" />}
    </div>
  </div>
);

export default SecurityInsights;
