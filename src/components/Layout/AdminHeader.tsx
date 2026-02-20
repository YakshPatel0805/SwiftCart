import { User, LogOut } from 'lucide-react';
import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { useState, useEffect, useRef } from 'react';

export default function AdminHeader() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [isUserMenuOpen, setIsUserMenuOpen] = useState(false);
  const userMenuRef = useRef<HTMLDivElement>(null);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (userMenuRef.current && !userMenuRef.current.contains(event.target as Node)) {
        setIsUserMenuOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  const handleLogout = () => {
    logout();
    setIsUserMenuOpen(false);
    navigate('/login');
  };
  
  const adminMenuItems = [
    { name: 'Admin Panel', path: '/admin' },
    { name: 'Profile', path: '/profile' },
    // { name: 'Orders', path: '/orders' },
  ];

  return (
    <header className="bg-white shadow-lg sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          {/* Logo */}
          <Link to="/admin" className="text-2xl font-bold text-blue-600 hover:text-blue-700 transition-colors">
            SwiftCart
          </Link>

          {/* Right Side */}
          <div className="flex items-center space-x-4">
            {/* User Menu */}
            <div className="relative" ref={userMenuRef}>
              <button
                onClick={() => setIsUserMenuOpen(!isUserMenuOpen)}
                className="flex items-center text-gray-700 hover:text-blue-600 transition-colors"
              >
                <User className="h-6 w-6" />
                {user && (
                  <span className="ml-2 text-sm font-medium hidden sm:block">
                    {user.username}
                  </span>
                )}
              </button>

              {isUserMenuOpen && (
                <div className="absolute right-0 mt-2 w-48 bg-white rounded-md shadow-lg py-1 z-50">
                  {adminMenuItems.map((item) => (
                    <Link
                      key={item.name}
                      to={item.path}
                      onClick={() => setIsUserMenuOpen(false)}
                      className="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                    >
                      {item.name}
                    </Link>
                  ))}
                  <hr className="my-1" />
                  <button
                    onClick={handleLogout}
                    className="flex items-center w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                  >
                    <LogOut className="h-4 w-4 mr-2" />
                    Logout
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Mobile Navigation */}
        <div className="md:hidden border-t py-3">
          <div className="flex flex-col space-y-2">
            <Link
              to="/admin/products"
              className="px-3 py-2 text-sm font-medium text-gray-700 hover:text-blue-600 hover:bg-gray-50 rounded-md transition-colors"
            >
              View Products
            </Link>
            <Link
              to="/admin/orders"
              className="px-3 py-2 text-sm font-medium text-gray-700 hover:text-blue-600 hover:bg-gray-50 rounded-md transition-colors"
            >
              View Orders
            </Link>
            <Link
              to="/admin"
              className="px-3 py-2 text-sm font-medium text-gray-700 hover:text-blue-600 hover:bg-gray-50 rounded-md transition-colors"
            >
              Admin Panel
            </Link>
          </div>
        </div>
      </div>
    </header>
  );
}
