import { Payment } from '../types';

export const PAYMENT_METHOD_LABELS: Record<string, string> = {
  'credit-card': 'Credit Card',
  'google-pay': 'Google Pay',
  'cash-on-delivery': 'Cash on Delivery',
  'Account-Transfer': 'Account Transfer'
};

export const getPaymentMethodLabel = (method: string): string => {
  return PAYMENT_METHOD_LABELS.hasOwnProperty(method) 
    ? PAYMENT_METHOD_LABELS[method] 
    : method;
};

export const getPaymentStatusColor = (status: string): string => {
  switch (status) {
    case 'success':
      return 'bg-green-100 text-green-800';
    case 'failed':
      return 'bg-red-100 text-red-800';
    case 'pending':
      return 'bg-yellow-100 text-yellow-800';
    case 'refunded':
      return 'bg-purple-100 text-purple-800';
    case 'cancelled':
      return 'bg-gray-100 text-gray-800';
    default:
      return 'bg-gray-100 text-gray-800';
  }
};

export const getPaymentStatusIcon = (status: string): string => {
  switch (status) {
    case 'success':
      return 'CheckCircle';
    case 'failed':
      return 'XCircle';
    case 'pending':
      return 'Clock';
    case 'refunded':
      return 'DollarSign';
    case 'cancelled':
      return 'XCircle';
    default:
      return 'AlertCircle';
  }
};

export const formatCurrency = (amount: number, currency: string = 'USD'): string => {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: currency
  }).format(amount);
};

export const formatPaymentData = (payment: Payment) => {
  return {
    amount: formatCurrency(payment.amount),
    method: getPaymentMethodLabel(payment.method),
    status: payment.status.charAt(0).toUpperCase() + payment.status.slice(1),
    transactionId: payment.transactionId || 'N/A',
    statusColor: getPaymentStatusColor(payment.status),
    statusIcon: getPaymentStatusIcon(payment.status)
  };
};

export const shouldShowTransactionId = (status: string, method: string): boolean => {
  return status === 'success' && method !== 'cash-on-delivery';
};
