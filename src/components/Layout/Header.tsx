import React from 'react';
import { useState, useEffect, useRef } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { Menu, X, ShoppingCart, User, Search, ChevronDown } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useCart } from '../../context/CartContext';
import { productsAPI } from '../../services/api';
import MobileMenu from './MobileMenu';

interface Category {
  category: string;
  count: number;
}

export default function Header() {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [isUserMenuOpen, setIsUserMenuOpen] = useState(false);
  const [isCategoryMenuOpen, setIsCategoryMenuOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [categories, setCategories] = useState<Category[]>([]);
  const [categorySearch, setCategorySearch] = useState('');
  const { user, logout } = useAuth();
  const { getTotalItems } = useCart();
  const navigate = useNavigate();
  const location = useLocation();
  
  const userMenuRef = useRef<HTMLDivElement>(null);
  const categoryMenuRef = useRef<HTMLDivElement>(null);

  // Fetch categories from backend
  useEffect(() => {
    const fetchCategories = async () => {
      try {
        const data = await productsAPI.getCategories();
        setCategories(data);
      } catch (error) {
        console.error('Error fetching categories:', error);
      }
    };
    fetchCategories();
  }, []);

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (userMenuRef.current && !userMenuRef.current.contains(event.target as Node)) {
        setIsUserMenuOpen(false);
      }
      if (categoryMenuRef.current && !categoryMenuRef.current.contains(event.target as Node)) {
        setIsCategoryMenuOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  const navigation = [
    { name: 'Home', path: '/' },
    { name: 'Contact', path: '/contact' },
  ];

  const userMenuItems = user ? [
    ...(user.role !== 'admin' ? [{ name: 'Dashboard', path: '/dashboard' }] : []),
    { name: 'Profile', path: '/profile' },
    { name: 'Orders', path: '/orders' },
    ...(user.role === 'admin' ? [{ name: 'Admin Panel', path: '/admin' }] : []),
  ] : [];

  // Filter categories based on search
  const filteredCategories = categories.filter(cat =>
    cat.category.toLowerCase().includes(categorySearch.toLowerCase())
  );

  const handleCategoryClick = (category: string) => {
    setIsCategoryMenuOpen(false);
    setCategorySearch('');
    navigate(`/category/${category}`);
  };

  const handleLogout = () => {
    logout();
    setIsUserMenuOpen(false);
    navigate('/login');
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      navigate(`/search?q=${encodeURIComponent(searchQuery.trim())}`);
      setSearchQuery('');
    }
  };

  const isActive = (path: string) => location.pathname === path;
  const isCategoryActive = () => categories.some(cat => location.pathname === `/category/${cat.category}`);
  const isAdminPage = location.pathname === '/admin';

  return (
    <header className="bg-white shadow-lg sticky top-0 z-50">
      <div className="mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          {/* Logo */}
          <Link to="/" className="text-2xl font-bold text-blue-600 hover:text-blue-700 transition-colors mr-10">
            SwiftCart
          </Link>

          {/* Desktop Navigation */}
          <nav className="hidden md:flex space-x-8 items-center">
            {!isAdminPage && (
              <>
                {navigation.map((item) => (
                  <Link
                    key={item.name}
                    to={item.path}
                    className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                      isActive(item.path)
                        ? 'text-blue-600 bg-blue-50'
                        : 'text-gray-700 hover:text-blue-600 hover:bg-gray-50'
                    }`}
                  >
                    {item.name}
                  </Link>
                ))}
                
                {/* Categories Dropdown */}
                <div className="relative" ref={categoryMenuRef}>
                  <button
                    onClick={() => setIsCategoryMenuOpen(!isCategoryMenuOpen)}
                    className={`flex items-center px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                      isCategoryActive()
                        ? 'text-blue-600 bg-blue-50'
                        : 'text-gray-700 hover:text-blue-600 hover:bg-gray-50'
                    }`}
                  >
                    Categories
                    <ChevronDown className={`ml-1 h-4 w-4 transition-transform ${isCategoryMenuOpen ? 'rotate-180' : ''}`} />
                  </button>

                  {isCategoryMenuOpen && (
                    <div className="absolute left-0 mt-2 w-80 bg-white rounded-md shadow-lg py-2 z-50 border border-gray-200">
                      {/* Search box for categories */}
                      <div className="px-3 pb-2">
                        <input
                          type="text"
                          placeholder="Search categories..."
                          value={categorySearch}
                          onChange={(e) => setCategorySearch(e.target.value)}
                          className="w-full px-3 py-2 text-sm border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                          onClick={(e) => e.stopPropagation()}
                        />
                      </div>

                      {/* Categories Grid */}
                      <div className="max-h-96 overflow-y-auto px-2">
                        {filteredCategories.length > 0 ? (
                          <div className="grid grid-cols-2 gap-1">
                            {filteredCategories.map((cat) => (
                              <button
                                key={cat.category}
                                onClick={() => handleCategoryClick(cat.category)}
                                className={`text-left px-3 py-2 text-sm rounded-md transition-colors ${
                                  location.pathname === `/category/${cat.category}`
                                    ? 'text-blue-600 bg-blue-50 font-medium'
                                    : 'text-gray-700 hover:bg-gray-100'
                                }`}
                              >
                                <div className="flex items-center justify-between">
                                  <span className="capitalize">{cat.category}</span>
                                  <span className="text-xs text-gray-500 ml-2">({cat.count})</span>
                                </div>
                              </button>
                            ))}
                          </div>
                        ) : (
                          <div className="px-3 py-4 text-sm text-gray-500 text-center">
                            No categories found
                          </div>
                        )}
                      </div>

                      {/* View All Categories Link */}
                      {categories.length > 0 && (
                        <div className="border-t mt-2 pt-2 px-3">
                          <Link
                            to="/category/all"
                            onClick={() => setIsCategoryMenuOpen(false)}
                            className="block text-sm text-blue-600 hover:text-blue-700 font-medium text-center py-1"
                          >
                            View All Products
                          </Link>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </>
            )}
          </nav>

          {/* Search Bar */}
          {!isAdminPage && (
            <div className="hidden lg:flex flex-1 max-w-md mx-8">
              <form onSubmit={handleSearch} className="relative w-full">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search products..."
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </form>
            </div>
          )}

          {/* Right Side */}
          <div className="flex items-center space-x-4">
            {/* Cart */}
            <Link
              to="/cart"
              className="relative p-2 text-gray-700 hover:text-blue-600 transition-colors"
            >
              <ShoppingCart className="h-6 w-6" />
              {getTotalItems() > 0 && (
                <span className="absolute -top-1 -right-1 bg-blue-600 text-white text-xs rounded-full h-5 w-5 flex items-center justify-center">
                  {getTotalItems()}
                </span>
              )}
            </Link>

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
                  {user ? (
                    <>
                      {userMenuItems.map((item) => (
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
                        className="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                      >
                        Logout
                      </button>
                    </>
                  ) : (
                    <>
                      <Link
                        to="/login"
                        onClick={() => setIsUserMenuOpen(false)}
                        className="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                      >
                        Login
                      </Link>
                      <Link
                        to="/signup"
                        onClick={() => setIsUserMenuOpen(false)}
                        className="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                      >
                        Sign Up
                      </Link>
                    </>
                  )}
                </div>
              )}
            </div>

            {/* Mobile menu button */}
            <button
              onClick={() => setIsMenuOpen(!isMenuOpen)}
              className="md:hidden p-2 text-gray-700 hover:text-blue-600 transition-colors"
            >
              {isMenuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
            </button>
          </div>
        </div>

        {/* Mobile Navigation */}
        {isMenuOpen && (
          <div className="md:hidden">
            <div className="px-2 pt-2 pb-3 space-y-1 sm:px-3 border-t">
              {!isAdminPage && (
                <>
                  {navigation.map((item) => (
                    <Link
                      key={item.name}
                      to={item.path}
                      onClick={() => setIsMenuOpen(false)}
                      className={`block w-full text-left px-3 py-2 rounded-md text-base font-medium transition-colors ${
                        isActive(item.path)
                          ? 'text-blue-600 bg-blue-50'
                          : 'text-gray-700 hover:text-blue-600 hover:bg-gray-50'
                      }`}
                    >
                      {item.name}
                    </Link>
                  ))}
                  
                  {/* Mobile Categories */}
                  <div className="pt-2">
                    <div className="px-3 py-2 text-xs font-semibold text-gray-500 uppercase tracking-wider">
                      Categories
                    </div>
                    <div className="px-3 pb-2">
                      <input
                        type="text"
                        placeholder="Search categories..."
                        value={categorySearch}
                        onChange={(e) => setCategorySearch(e.target.value)}
                        className="w-full px-3 py-2 text-sm border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
                      />
                    </div>
                    <div className="max-h-64 overflow-y-auto">
                      {filteredCategories.map((cat) => (
                        <button
                          key={cat.category}
                          onClick={() => {
                            handleCategoryClick(cat.category);
                            setIsMenuOpen(false);
                          }}
                          className={`block w-full text-left px-3 py-2 rounded-md text-base font-medium transition-colors ${
                            location.pathname === `/category/${cat.category}`
                              ? 'text-blue-600 bg-blue-50'
                              : 'text-gray-700 hover:text-blue-600 hover:bg-gray-50'
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <span className="capitalize">{cat.category}</span>
                            <span className="text-xs text-gray-500">({cat.count})</span>
                          </div>
                        </button>
                      ))}
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Mobile Menu Component */}
      <MobileMenu isOpen={isMenuOpen} onClose={() => setIsMenuOpen(false)} />
    </header>
  );
}
