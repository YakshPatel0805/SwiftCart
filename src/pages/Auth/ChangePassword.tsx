import React, { useState } from 'react';
import { Lock, Eye, EyeOff, Check, X, Mail } from 'lucide-react';
import { authAPI } from '../../services/api';

export default function ChangePassword() {
  const [formData, setFormData] = useState({
    email: '',
    oldPassword: '',
    newPassword: '',
    confirmPassword: '',
  });
  const [showOldPassword, setShowOldPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess(false);
    setIsLoading(true);

    try {
      const email = formData.email.trim();
      const oldPassword = formData.oldPassword.trim();
      const newPassword = formData.newPassword.trim();
      const confirmPassword = formData.confirmPassword.trim();

      if (!email || !oldPassword || !newPassword || !confirmPassword) {
        setError('All fields are required');
        setIsLoading(false);
        return;
      }

      if (newPassword !== confirmPassword) {
        setError('New passwords do not match');
        setIsLoading(false);
        return;
      }

      if (newPassword.length < 6) {
        setError('Password must be at least 6 characters long');
        setIsLoading(false);
        return;
      }

      if (oldPassword === newPassword) {
        setError('New password must be different from current password');
        setIsLoading(false);
        return;
      }

      const result = await authAPI.changePassword(
        email,
        oldPassword,
        newPassword,
        confirmPassword
      );

      if (result.message && !result.message.includes('error')) {
        setSuccess(true);
        setFormData({
          email: '',
          oldPassword: '',
          newPassword: '',
          confirmPassword: '',
        });
        setTimeout(() => {
          setSuccess(false);
        }, 5000);
      } else {
        setError(result.message || 'Failed to change password');
      }
    } catch (err) {
      setError('An error occurred. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="bg-white shadow-md min-h-screen flex items-center justify-center bg-gray-100 p-6">

      {error && (
        <div className="mb-4 rounded-md bg-red-50 p-4 flex items-start">
          <X className="h-5 w-5 text-red-400 mt-0.5 mr-3 flex-shrink-0" />
          <div>
            <h3 className="text-sm font-medium text-red-800">{error}</h3>
          </div>
        </div>
      )}

      {success && (
        <div className="mb-4 rounded-md bg-green-50 p-4 flex items-start">
          <Check className="h-5 w-5 text-green-400 mt-0.5 mr-3 flex-shrink-0" />
          <div>
            <h3 className="text-sm font-medium text-green-800">
              Password changed successfully!
            </h3>
          </div>
        </div>
      )}

      <div className='flex items-center justify-center pr-10 w-2/3'>
        <form onSubmit={handleSubmit} className="bg-white p-6 rounded-lg shadow-md space-y-5 w-full max-w-md">
          <div className='text-2xl font-bold text-gray-900 mb-6'>Change Password</div>
          <div>
            <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-2">
              Email Address
            </label>
            <div className="relative">
              <Mail className="absolute left-3 top-3 h-5 w-5 text-gray-400" />
              <input
                id="email"
                name="email"
                type="email"
                autoComplete="email"
                required
                value={formData.email}
                onChange={handleInputChange}
                className="appearance-none block w-full pl-10 pr-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                placeholder="Enter your email address"
              />
            </div>
          </div>

          <div>
            <label htmlFor="oldPassword" className="block text-sm font-medium text-gray-700 mb-2">
              Current Password
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-3 h-5 w-5 text-gray-400" />
              <input
                id="oldPassword"
                name="oldPassword"
                type={showOldPassword ? 'text' : 'password'}
                autoComplete="current-password"
                required
                value={formData.oldPassword}
                onChange={handleInputChange}
                className="appearance-none block w-full pl-10 pr-10 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                placeholder="Enter your current password"
              />
              <button
                type="button"
                onClick={() => setShowOldPassword(!showOldPassword)}
                className="absolute right-3 top-3 text-gray-400 hover:text-gray-600"
              >
                {showOldPassword ? (
                  <EyeOff className="h-5 w-5" />
                ) : (
                  <Eye className="h-5 w-5" />
                )}
              </button>
            </div>
          </div>

          <div>
            <label htmlFor="newPassword" className="block text-sm font-medium text-gray-700 mb-2">
              New Password
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-3 h-5 w-5 text-gray-400" />
              <input
                id="newPassword"
                name="newPassword"
                type={showNewPassword ? 'text' : 'password'}
                autoComplete="new-password"
                required
                value={formData.newPassword}
                onChange={handleInputChange}
                className="appearance-none block w-full pl-10 pr-10 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                placeholder="Enter new password"
              />
              <button
                type="button"
                onClick={() => setShowNewPassword(!showNewPassword)}
                className="absolute right-3 top-3 text-gray-400 hover:text-gray-600"
              >
                {showNewPassword ? (
                  <EyeOff className="h-5 w-5" />
                ) : (
                  <Eye className="h-5 w-5" />
                )}
              </button>
            </div>
            <p className="mt-1 text-sm text-gray-500">
              Must be at least 6 characters long
            </p>
          </div>

          <div>
            <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 mb-2">
              Confirm New Password
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-3 h-5 w-5 text-gray-400" />
              <input
                id="confirmPassword"
                name="confirmPassword"
                type={showConfirmPassword ? 'text' : 'password'}
                autoComplete="new-password"
                required
                value={formData.confirmPassword}
                onChange={handleInputChange}
                className="appearance-none block w-full pl-10 pr-10 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                placeholder="Confirm new password"
              />
              <button
                type="button"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                className="absolute right-3 top-3 text-gray-400 hover:text-gray-600"
              >
                {showConfirmPassword ? (
                  <EyeOff className="h-5 w-5" />
                ) : (
                  <Eye className="h-5 w-5" />
                )}
              </button>
            </div>
          </div>

          <div className="flex gap-4">
            <button
              type="submit"
              disabled={isLoading}
              className="flex-1 flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? 'Updating...' : 'Update Password'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
