// import React from 'react';
import { Package, ShoppingCart, Heart, User, CreditCard } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useCart } from '../context/CartContext';

interface DashboardProps {
  onPageChange: (page: string) => void;
}

export default function Dashboard({ onPageChange }: DashboardProps) {
  const { user } = useAuth();
  const { getTotalItems } = useCart();

  const stats = [
    {
      label: 'Items in Cart',
      value: getTotalItems(),
      icon: ShoppingCart,
      color: 'blue',
    },
    {
      label: 'Total Orders',
      value: '0',
      icon: Package,
      color: 'green',
    },
    {
      label: 'Wishlist Items',
      value: '0',
      icon: Heart,
      color: 'red',
    },
  ];

  const quickActions = [
    {
      label: 'View Cart',
      description: 'Review items in your shopping cart',
      icon: ShoppingCart,
      action: () => onPageChange('cart'),
      color: 'blue',
    },
    {
      label: 'My Orders',
      description: 'Track your order history',
      icon: Package,
      action: () => onPageChange('orders'),
      color: 'green',
    },
    {
      label: 'Profile Settings',
      description: 'Update your personal information',
      icon: User,
      action: () => onPageChange('profile'),
      color: 'purple',
    },
    {
      label: 'Payment Methods',
      description: 'Manage your payment options',
      icon: CreditCard,
      action: () => onPageChange('profile'),
      color: 'orange',
    },
  ];

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900">
            Welcome back, {user?.username}!
          </h1>
          <p className="text-gray-600 mt-2">
            Here's what's happening with your account today.
          </p>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          {stats.map((stat, index) => (
            <div key={index} className="bg-white p-6 rounded-lg shadow-md">
              <div className="flex items-center">
                <div className={`p-3 rounded-lg bg-${stat.color}-100`}>
                  <stat.icon className={`h-6 w-6 text-${stat.color}-600`} />
                </div>
                <div className="ml-4">
                  <p className="text-2xl font-bold text-gray-900">{stat.value}</p>
                  <p className="text-gray-600">{stat.label}</p>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Quick Actions */}
        <div className="bg-white rounded-lg shadow-md p-6 mb-8">
          <h2 className="text-xl font-bold text-gray-900 mb-6">Quick Actions</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {quickActions.map((action, index) => (
              <button
                key={index}
                onClick={action.action}
                className="p-4 border border-gray-200 rounded-lg hover:border-blue-300 hover:shadow-md transition-all text-left"
              >
                <div className="flex items-center space-x-3">
                  <div className={`p-2 rounded-lg bg-${action.color}-100`}>
                    <action.icon className={`h-5 w-5 text-${action.color}-600`} />
                  </div>
                  <div>
                    <h3 className="font-medium text-gray-900">{action.label}</h3>
                    <p className="text-sm text-gray-600">{action.description}</p>
                  </div>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Recent Activity */}
        <div className="bg-white rounded-lg shadow-md p-6">
          <h2 className="text-xl font-bold text-gray-900 mb-6">Recent Activity</h2>
          <div className="text-center py-8">
            <Package className="h-12 w-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-500">No recent activity to show.</p>
            <button
              onClick={() => onPageChange('home')}
              className="mt-4 bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors"
            >
              Start Shopping
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}