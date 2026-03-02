import React from 'react';
import { X, Home, ShoppingBag, User, Menu } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';

interface MobileMenuProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function MobileMenu({ isOpen, onClose }: MobileMenuProps) {
  const navigate = useNavigate();
  const { user, logout } = useAuth();

  const handleNav = (path: string) => {
    navigate(path);
    onClose();
  };

  return (
    <>
      {/* Overlay */}
      <div
        className={`fixed inset-0 bg-black bg-opacity-50 z-40 transition-opacity duration-300 ${
          isOpen ? 'opacity-100' : 'opacity-0 pointer-events-none'
        }`}
        onClick={onClose}
      />

      {/* Menu */}
      <div
        className={`fixed top-0 left-0 h-full w-64 bg-white shadow-lg z-50 transition-transform duration-300 ease-in-out ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="p-4 border-b flex justify-between items-center">
          <h2 className="text-xl font-bold text-gray-900">Menu</h2>
          <button onClick={onClose} className="p-2 hover:bg-gray-100 rounded-lg">
            <X className="w-6 h-6 text-gray-600" />
          </button>
        </div>

        <nav className="p-4 space-y-2">
          <button
            onClick={() => handleNav('/')}
            className="flex items-center gap-3 w-full p-3 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <Home className="w-5 h-5 text-gray-600" />
            <span className="text-gray-700">Home</span>
          </button>

          <button
            onClick={() => handleNav('/cart')}
            className="flex items-center gap-3 w-full p-3 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <ShoppingBag className="w-5 h-5 text-gray-600" />
            <span className="text-gray-700">Cart</span>
          </button>

          {user ? (
            <>
              <button
                onClick={() => handleNav('/profile')}
                className="flex items-center gap-3 w-full p-3 hover:bg-gray-100 rounded-lg transition-colors"
              >
                <User className="w-5 h-5 text-gray-600" />
                <span className="text-gray-700">Profile</span>
              </button>

              <button
                onClick={() => handleNav('/orders')}
                className="flex items-center gap-3 w-full p-3 hover:bg-gray-100 rounded-lg transition-colors"
              >
                <ShoppingBag className="w-5 h-5 text-gray-600" />
                <span className="text-gray-700">Orders</span>
              </button>

              {user.role === 'admin' && (
                <button
                  onClick={() => handleNav('/admin')}
                  className="flex items-center gap-3 w-full p-3 hover:bg-gray-100 rounded-lg transition-colors"
                >
                  <span className="text-gray-600">Admin Panel</span>
                </button>
              )}

              <button
                onClick={logout}
                className="flex items-center gap-3 w-full p-3 hover:bg-red-50 rounded-lg transition-colors text-red-600"
              >
                <span className="text-gray-600">Logout</span>
              </button>
            </>
          ) : (
            <button
              onClick={() => handleNav('/login')}
              className="flex items-center gap-3 w-full p-3 hover:bg-gray-100 rounded-lg transition-colors"
            >
              <User className="w-5 h-5 text-gray-600" />
              <span className="text-gray-700">Login</span>
            </button>
          )}
        </nav>
      </div>
    </>
  );
}
