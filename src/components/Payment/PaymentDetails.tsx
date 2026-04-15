import { CheckCircle, XCircle, AlertCircle, Clock } from 'lucide-react';
import { PaymentDetailsProps } from '../../types';
import {
  getPaymentMethodLabel,
  getPaymentStatusColor,
  formatCurrency,
  shouldShowTransactionId
} from '../../utils/paymentUtils';

export default function PaymentDetails({
  paymentData,
  loading = false,
  error = undefined
}: PaymentDetailsProps) {
  if (loading) {
    return (
      <div className="bg-gray-50 rounded-lg p-4 animate-pulse">
        <div className="h-4 bg-gray-200 rounded w-1/3 mb-3"></div>
        <div className="space-y-2">
          <div className="h-3 bg-gray-200 rounded w-1/3"></div>
          <div className="h-3 bg-gray-200 rounded w-1/2"></div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-lg p-4">
        <div className="flex items-center gap-2 text-red-800">
          <AlertCircle className="h-5 w-5 flex-shrink-0" />
          <p className="text-sm font-medium">{error}</p>
        </div>
      </div>
    );
  }

  if (!paymentData) {
    return (
      <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
        <div className="flex items-center gap-2 text-yellow-800">
          <AlertCircle className="h-5 w-5 flex-shrink-0" />
          <p className="text-sm font-medium">Payment information not available</p>
        </div>
      </div>
    );
  }

  const statusColor = getPaymentStatusColor(paymentData.status);
  const methodLabel = getPaymentMethodLabel(paymentData.method);
  const showTransactionId = shouldShowTransactionId(paymentData.status, paymentData.method);

  const getStatusIcon = () => {
    switch (paymentData.status) {
      case 'success':
        return <CheckCircle className="h-5 w-5" />;
      case 'failed':
        return <XCircle className="h-5 w-5" />;
      case 'pending':
        return <Clock className="h-5 w-5" />;
      default:
        return <AlertCircle className="h-5 w-5" />;
    }
  };

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-4">
      <h3 className="text-lg font-semibold text-gray-900 mb-4">Payment Details</h3>
      
      <div className="space-y-3">
        {/* Payment Amount */}
        <div className="flex justify-between items-center">
          <span className="text-gray-600 font-medium">Amount:</span>
          <span className="text-lg font-bold text-gray-900">
            {formatCurrency(paymentData.amount)}
          </span>
        </div>

        {/* Payment Method */}
        <div className="flex justify-between items-center">
          <span className="text-gray-600 font-medium">Method:</span>
          <span className="text-gray-900">{methodLabel}</span>
        </div>

        {/* Payment Status */}
        <div className="flex justify-between items-center">
          <span className="text-gray-600 font-medium">Status:</span>
          <span className={`px-3 py-1 rounded-full text-sm font-medium flex items-center gap-1 ${statusColor}`}>
            {getStatusIcon()}
            {paymentData.status.charAt(0).toUpperCase() + paymentData.status.slice(1)}
          </span>
        </div>

        {/* Transaction ID - only show for successful payments */}
        {showTransactionId && (
          <div className="flex justify-between items-center pt-2 border-t border-gray-200">
            <span className="text-gray-600 font-medium">Transaction ID:</span>
            <span className="text-gray-900 font-mono text-sm bg-gray-50 px-2 py-1 rounded">
              {paymentData.transactionId}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
