import { useState, useEffect } from 'react';
import { Plus, X, CreditCard, Wallet, Smartphone, Trash2, Star } from 'lucide-react';
import { bankAPI } from '../services/api';

interface BankAccount {
  _id: string; // Will be 'bank-account', 'credit-card', or 'google-pay'
  bankAccount?: {
    accountHolderName: string;
    accountNumber: string;
    balance: number;
    isDefault: boolean;
  };
  creditCard?: {
    cardHolderName: string;
    cardNumber: string;
    cardBalance: number;
    isDefault: boolean;
  };
  googlePay?: {
    mobileNumber: string;
    upiId: string;
    balance: number;
    isDefault: boolean;
  };
  isDefault: boolean;
  createdAt: string;
}

export default function AddAccount() {
  const [accounts, setAccounts] = useState<BankAccount[]>([]);
  const [loading, setLoading] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [accountType, setAccountType] = useState<'bank-account' | 'credit-card' | 'google-pay'>('bank-account');
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const [formData, setFormData] = useState({
    // Bank Account
    accountHolderName: '',
    accountNumber: '',
    accountPIN: '',
    balance: '',
    // Credit Card
    cardHolderName: '',
    cardNumber: '',
    cardCVV: '',
    cardExpiry: '',
    cardBalance: '',
    // Google Pay
    mobileNumber: '',
    upiId: '',
    googlePayPIN: ''
  });

  useEffect(() => {
    loadAccounts();
  }, []);

  const loadAccounts = async () => {
    try {
      setLoading(true);
      const data = await bankAPI.getAll();
      setAccounts(data);
      console.log('✓ Bank accounts loaded:', data.length);
    } catch (error: any) {
      console.error('Error loading accounts:', error);
      setMessage({ type: 'error', text: `Failed to load accounts: ${error.message}` });
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setMessage(null);

    try {
      let accountData: any = {};

      if (accountType === 'bank-account') {
        if (!formData.accountHolderName || !formData.accountNumber || !formData.accountPIN) {
          setMessage({ type: 'error', text: 'Please fill all bank account fields' });
          setSubmitting(false);
          return;
        }
        accountData.bankAccount = {
          accountHolderName: formData.accountHolderName,
          accountNumber: formData.accountNumber,
          accountPIN: formData.accountPIN,
          balance: parseFloat(formData.balance) || 0
        };
      } else if (accountType === 'credit-card') {
        if (!formData.cardHolderName || !formData.cardNumber || !formData.cardCVV || !formData.cardExpiry) {
          setMessage({ type: 'error', text: 'Please fill all credit card fields' });
          setSubmitting(false);
          return;
        }
        accountData.creditCard = {
          cardHolderName: formData.cardHolderName,
          cardNumber: formData.cardNumber,
          cardCVV: formData.cardCVV,
          cardExpiry: formData.cardExpiry,
          cardBalance: parseFloat(formData.cardBalance) || 0
        };
      } else if (accountType === 'google-pay') {
        if (!formData.mobileNumber || !formData.upiId) {
          setMessage({ type: 'error', text: 'Please fill all Google Pay fields' });
          setSubmitting(false);
          return;
        }
        accountData.googlePay = {
          mobileNumber: formData.mobileNumber,
          upiId: formData.upiId,
          PIN: formData.googlePayPIN
        };
      }

      await bankAPI.add(accountData);
      setMessage({ type: 'success', text: 'Account added successfully!' });
      setFormData({
        accountHolderName: '',
        accountNumber: '',
        accountPIN: '',
        balance: '',
        cardHolderName: '',
        cardNumber: '',
        cardCVV: '',
        cardExpiry: '',
        cardBalance: '',
        mobileNumber: '',
        upiId: '',
        googlePayPIN: ''
      });
      setShowForm(false);
      await loadAccounts();
    } catch (error: any) {
      console.error('Error adding account:', error);
      setMessage({ type: 'error', text: `Failed to add account: ${error.message}` });
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (accountId: string) => {
    if (!window.confirm('Are you sure you want to delete this account?')) return;

    try {
      setDeletingId(accountId);
      await bankAPI.delete(accountId);
      setMessage({ type: 'success', text: 'Account deleted successfully' });
      await loadAccounts();
    } catch (error: any) {
      console.error('Error deleting account:', error);
      setMessage({ type: 'error', text: `Failed to delete account: ${error.message}` });
    } finally {
      setDeletingId(null);
    }
  };

  const handleSetDefault = async (accountId: string) => {
    try {
      await bankAPI.setDefault(accountId);
      setMessage({ type: 'success', text: 'Default account updated' });
      await loadAccounts();
    } catch (error: any) {
      console.error('Error setting default:', error);
      setMessage({ type: 'error', text: `Failed to set default: ${error.message}` });
    }
  };

  const getAccountIcon = (type: string) => {
    switch (type) {
      case 'bank-account':
        return <Wallet className="h-5 w-5 text-blue-600" />;
      case 'credit-card':
        return <CreditCard className="h-5 w-5 text-purple-600" />;
      case 'google-pay':
        return <Smartphone className="h-5 w-5 text-green-600" />;
      default:
        return <Wallet className="h-5 w-5" />;
    }
  };

  const getAccountDisplay = (account: BankAccount) => {
    if (account.bankAccount) {
      return {
        title: account.bankAccount.accountHolderName || 'Bank Account',
        subtitle: `Account: ****${account.bankAccount.accountNumber?.slice(-4)}`,
        balance: `₹${account.bankAccount.balance.toFixed(2)}`
      };
    }
    if (account.creditCard) {
      return {
        title: account.creditCard.cardHolderName || 'Credit Card',
        subtitle: `Card: ****${account.creditCard.cardNumber?.slice(-4)}`,
        balance: `₹${account.creditCard.cardBalance.toFixed(2)}`
      };
    }
    if (account.googlePay) {
      return {
        title: 'Google Pay',
        subtitle: `UPI: ${account.googlePay.upiId}`,
        balance: `₹${account.googlePay.balance?.toFixed(2) || '0.00'}`
      };
    }
    return { title: 'Account', subtitle: '', balance: '' };
  };

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-semibold text-gray-900">Payment Methods</h2>
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          <Plus className="h-4 w-4" />
          {showForm ? 'Cancel' : 'Add Account'}
        </button>
      </div>

      {message && (
        <div
          className={`mb-4 p-4 rounded-md ${
            message.type === 'success'
              ? 'bg-green-50 text-green-800 border border-green-200'
              : 'bg-red-50 text-red-800 border border-red-200'
          }`}
        >
          {message.text}
        </div>
      )}

      {/* Add Account Form */}
      {showForm && (
        <div className="mb-6 p-6 bg-gray-50 rounded-lg border border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Add New Payment Method</h3>

          {/* Account Type Selection */}
          <div className="mb-6">
            <label className="block text-sm font-medium text-gray-700 mb-3">Account Type</label>
            <div className="grid grid-cols-3 gap-3">
              {(['bank-account', 'credit-card', 'google-pay'] as const).map(type => (
                <button
                  key={type}
                  onClick={() => setAccountType(type)}
                  className={`p-3 rounded-lg border-2 transition-colors flex items-center justify-center gap-2 ${
                    accountType === type
                      ? 'border-blue-600 bg-blue-50'
                      : 'border-gray-200 bg-white hover:border-gray-300'
                  }`}
                >
                  {getAccountIcon(type)}
                  <span className="text-sm font-medium capitalize">
                    {type === 'bank-account' ? 'Bank' : type === 'credit-card' ? 'Card' : 'Google Pay'}
                  </span>
                </button>
              ))}
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Bank Account Form */}
            {accountType === 'bank-account' && (
              <>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Account Holder Name</label>
                  <input
                    type="text"
                    value={formData.accountHolderName}
                    onChange={(e) => setFormData({ ...formData, accountHolderName: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                    placeholder="John Doe"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Account Number</label>
                  <input
                    type="text"
                    value={formData.accountNumber}
                    onChange={(e) => setFormData({ ...formData, accountNumber: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                    placeholder="1234567890"
                    required
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Account PIN</label>
                    <input
                      type="password"
                      value={formData.accountPIN}
                      onChange={(e) => setFormData({ ...formData, accountPIN: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                      placeholder="****"
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Balance</label>
                    <input
                      type="number"
                      value={formData.balance}
                      onChange={(e) => setFormData({ ...formData, balance: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                      placeholder="0"
                    />
                  </div>
                </div>
              </>
            )}

            {/* Credit Card Form */}
            {accountType === 'credit-card' && (
              <>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Card Holder Name</label>
                  <input
                    type="text"
                    value={formData.cardHolderName}
                    onChange={(e) => setFormData({ ...formData, cardHolderName: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                    placeholder="John Doe"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Card Number</label>
                  <input
                    type="text"
                    value={formData.cardNumber}
                    onChange={(e) => setFormData({ ...formData, cardNumber: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                    placeholder="1234 5678 9012 3456"
                    required
                  />
                </div>
                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">CVV</label>
                    <input
                      type="password"
                      value={formData.cardCVV}
                      onChange={(e) => setFormData({ ...formData, cardCVV: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                      placeholder="***"
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Expiry (MM/YY)</label>
                    <input
                      type="text"
                      value={formData.cardExpiry}
                      onChange={(e) => setFormData({ ...formData, cardExpiry: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                      placeholder="12/25"
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Balance</label>
                    <input
                      type="number"
                      value={formData.cardBalance}
                      onChange={(e) => setFormData({ ...formData, cardBalance: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                      placeholder="0"
                    />
                  </div>
                </div>
              </>
            )}

            {/* Google Pay Form */}
            {accountType === 'google-pay' && (
              <>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Mobile Number</label>
                  <input
                    type="tel"
                    value={formData.mobileNumber}
                    onChange={(e) => setFormData({ ...formData, mobileNumber: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                    placeholder="9876543210"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">UPI ID</label>
                  <input
                    type="text"
                    value={formData.upiId}
                    onChange={(e) => setFormData({ ...formData, upiId: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                    placeholder="user@upi"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">PIN</label>
                  <input
                    type="password"
                    value={formData.googlePayPIN}
                    onChange={(e) => setFormData({ ...formData, googlePayPIN: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                    placeholder="****"
                  />
                </div>
              </>
            )}

            <button
              type="submit"
              disabled={submitting}
              className="w-full bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
              {submitting ? 'Adding...' : 'Add Account'}
            </button>
          </form>
        </div>
      )}

      {/* Accounts List */}
      {loading ? (
        <div className="text-center py-8 text-gray-500">Loading accounts...</div>
      ) : accounts.length === 0 ? (
        <div className="text-center py-12">
          <Wallet className="h-16 w-16 text-gray-400 mx-auto mb-4" />
          <p className="text-gray-500">No payment methods added yet</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {accounts.map((account) => {
            const display = getAccountDisplay(account);
            return (
              <div
                key={account._id}
                className={`p-4 rounded-lg border-2 transition-colors ${
                  account.isDefault ? 'border-blue-600 bg-blue-50' : 'border-gray-200 bg-gray-50'
                }`}
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3">
                    {getAccountIcon(account.bankAccount ? 'bank-account' : account.creditCard ? 'credit-card' : 'google-pay')}
                    <div>
                      <h4 className="font-semibold text-gray-900">{display.title}</h4>
                      <p className="text-sm text-gray-600">{display.subtitle}</p>
                    </div>
                  </div>
                  {account.isDefault && (
                    <span className="flex items-center gap-1 px-2 py-1 bg-blue-100 text-blue-700 text-xs font-semibold rounded">
                      <Star className="h-3 w-3" />
                      Default
                    </span>
                  )}
                </div>

                <div className="mb-3 text-sm">
                  <span className="text-gray-600">Balance: </span>
                  <span className="font-semibold text-gray-900">{display.balance}</span>
                </div>

                <div className="flex gap-2">
                  {!account.isDefault && (
                    <button
                      onClick={() => handleSetDefault(account._id)}
                      className="flex-1 px-3 py-2 text-sm bg-blue-100 text-blue-700 rounded hover:bg-blue-200 transition-colors"
                    >
                      Set Default
                    </button>
                  )}
                  <button
                    onClick={() => handleDelete(account._id)}
                    disabled={deletingId === account._id}
                    className="px-3 py-2 text-sm bg-red-100 text-red-700 rounded hover:bg-red-200 disabled:opacity-50 transition-colors flex items-center gap-1"
                  >
                    <Trash2 className="h-4 w-4" />
                    Delete
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
