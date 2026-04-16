import { User, LogOut, Moon, Sun, Bell, Trash2, Check, Clock } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import { useState, useEffect, useRef } from 'react';
import { useNotification } from '../../context/NotificationContext';
import { ordersAPI } from '../../services/api';

export default function AdminHeader() {
  const { user, logout } = useAuth();
  const { isDarkMode, toggleTheme } = useTheme();
  const { showNotification, notifications, unreadCount, markAllAsRead, clearNotifications } = useNotification();
  const navigate = useNavigate();
  const [isUserMenuOpen, setIsUserMenuOpen] = useState(false);
  const [isNotificationsOpen, setIsNotificationsOpen] = useState(false);
  const userMenuRef = useRef<HTMLDivElement>(null);
  const notificationsMenuRef = useRef<HTMLDivElement>(null);
  const notifiedIdsRef = useRef<Set<string>>(new Set());
  const lastNotifiedTimeRef = useRef<string>(new Date(Date.now() - 5 * 60 * 1000).toISOString()); // 5-minute buffer initially

  useEffect(() => {
    const checkUpdates = async () => {
      try {
        console.log('AdminHeader: Checking for updates since ', lastNotifiedTimeRef.current);
        const recentOrders = await ordersAPI.getRecentNotifications();
        
        if (!recentOrders || !Array.isArray(recentOrders)) {
          console.warn('AdminHeader: Notification result is not valid array');
          return;
        }

        // Filter for orders updated after our last check (with buffer)
        const newUpdates = recentOrders.filter((order: any) => {
          const updateDate = order.updatedAt || order.createdAt;
          if (!updateDate) return false;
          
          const eventKey = `${order._id}_${order.status}`;
          if (notifiedIdsRef.current.has(eventKey)) return false;

          // Simple date check with buffer to ensure we don't miss anything
          return new Date(updateDate) > new Date(lastNotifiedTimeRef.current);
        });

        if (newUpdates.length > 0) {
          console.log(`AdminHeader: Found ${newUpdates.length} new updates!`);
          newUpdates.forEach((order: any) => {
            const eventKey = `${order._id}_${order.status}`;
            notifiedIdsRef.current.add(eventKey);

            const customerName = order.userId?.username || order.shippingAddress?.name || 'Customer';
            let message = '';
            let type: any = 'info';

            switch (order.status) {
              case 'pending':
                message = `New order received from ${customerName}`;
                type = 'success';
                break;
              case 'cancelled':
                message = `Order #${order._id.slice(-6)} was cancelled by ${customerName}`;
                type = 'error';
                break;
              case 'delivered':
                message = `Order #${order._id.slice(-6)} has been delivered to ${customerName}`;
                type = 'success';
                break;
            }

            if (message) {
              showNotification(message, type, true); // persist: true
            }
          });
          
          // Update the last notified time to the most recent update among the new ones
          // We keep a 2-second overlap buffer for the next poll
          const mostRecent = newUpdates.reduce((latest: string, current: any) => {
            const currentDate = current.updatedAt || current.createdAt;
            return new Date(currentDate) > new Date(latest) ? currentDate : latest;
          }, lastNotifiedTimeRef.current);
          
          lastNotifiedTimeRef.current = mostRecent;
        }
      } catch (error) {
        console.error('Error polling for order updates:', error);
      }
    };

    // Establishing baseline - Mark all currently recent orders as "seen" to avoid flooding on refresh
    const initBaseline = async () => {
       try {
         const recent = await ordersAPI.getRecentNotifications();
         recent.forEach((o: any) => notifiedIdsRef.current.add(`${o._id}_${o.status}`));
         if (recent.length > 0) {
           lastNotifiedTimeRef.current = recent[0].updatedAt || recent[0].createdAt;
         }
       } catch (e) {
         console.warn('Failed to establish baseline:', e);
       }
    };
    
    initBaseline().then(() => {
       // Start polling every 30 seconds
       const interval = setInterval(checkUpdates, 30000);
       return () => clearInterval(interval);
    });

  }, [showNotification]);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (userMenuRef.current && !userMenuRef.current.contains(event.target as Node)) {
        setIsUserMenuOpen(false);
      }
      if (notificationsMenuRef.current && !notificationsMenuRef.current.contains(event.target as Node)) {
        setIsNotificationsOpen(false);
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

  const handleOpenNotifications = () => {
    setIsNotificationsOpen(!isNotificationsOpen);
    if (!isNotificationsOpen) {
      markAllAsRead();
    }
  };

  const getTimeAgo = (timestamp: string) => {
    const seconds = Math.floor((new Date().getTime() - new Date(timestamp).getTime()) / 1000);
    if (seconds < 60) return `${seconds}s ago`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    return new Date(timestamp).toLocaleDateString();
  };
  
  const adminMenuItems = [
    { name: 'Admin Panel', path: '/admin' },
    { name: 'Profile', path: '/profile' },
  ];

  return (
    <header className="bg-white dark:bg-gray-900 shadow-lg sticky top-0 z-50 transition-colors duration-200">
      <div className="mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          {/* Logo */}
          <Link to="/admin" className="text-2xl font-bold text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 transition-colors">
            SwiftCart
          </Link>

          {/* Right Side */}
          <div className="flex items-center space-x-4">
            {/* Theme Toggle */}
            <button
              onClick={toggleTheme}
              className="p-2 text-gray-700 dark:text-gray-200 hover:text-blue-600 dark:hover:text-blue-400 transition-colors rounded-full hover:bg-gray-100 dark:hover:bg-gray-700"
              aria-label="Toggle theme"
            >
              {isDarkMode ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
            </button>

            {/* Notifications Bell */}
            <div className="relative" ref={notificationsMenuRef}>
              <button
                onClick={handleOpenNotifications}
                className="p-2 text-gray-700 dark:text-gray-200 hover:text-blue-600 dark:hover:text-blue-400 transition-colors rounded-full hover:bg-gray-100 dark:hover:bg-gray-700 relative"
                aria-label="Notifications"
              >
                <Bell className="h-5 w-5" />
                {unreadCount > 0 && (
                  <span className="absolute top-0 right-0 inline-flex items-center justify-center px-1.5 py-0.5 text-xs font-bold leading-none text-white transform translate-x-1/2 -translate-y-1/2 bg-red-600 rounded-full border-2 border-white dark:border-gray-900">
                    {unreadCount}
                  </span>
                )}
              </button>

              {isNotificationsOpen && (
                <div className="absolute right-0 mt-3 w-80 bg-white dark:bg-gray-900 rounded-lg shadow-xl z-[100] border border-gray-200 dark:border-gray-700 overflow-hidden">
                  <div className="p-3 border-b border-gray-100 dark:border-gray-800 flex justify-between items-center bg-gray-50 dark:bg-gray-800/50">
                    <h3 className="text-sm font-bold text-gray-900 dark:text-white flex items-center gap-2">
                      <Bell className="h-4 w-4 text-blue-500" />
                      Notifications
                    </h3>
                    <div className="flex gap-2">
                       <button 
                        onClick={clearNotifications}
                        className="text-[10px] text-gray-500 hover:text-red-500 transition-colors flex items-center gap-1"
                        title="Clear all"
                      >
                        <Trash2 className="h-3 w-3" />
                        Clear
                      </button>
                    </div>
                  </div>
                  
                  <div className="max-h-[400px] overflow-y-auto">
                    {notifications.length === 0 ? (
                      <div className="p-8 text-center">
                        <Bell className="h-10 w-10 text-gray-200 dark:text-gray-800 mx-auto mb-3" />
                        <p className="text-sm text-gray-500 dark:text-gray-400">No notifications yet</p>
                      </div>
                    ) : (
                      <div className="divide-y divide-gray-100 dark:divide-gray-800">
                        {notifications.map((n) => (
                          <div 
                            key={n.id} 
                            className={`p-4 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors ${!n.read ? 'bg-blue-50/30 dark:bg-blue-900/10' : ''}`}
                          >
                            <div className="flex gap-3">
                              <div className={`p-2 rounded-full h-fit mt-0.5 ${
                                n.type === 'error' ? 'bg-red-100 text-red-600' : 
                                n.type === 'info' ? 'bg-blue-100 text-blue-600' : 
                                'bg-green-100 text-green-600'
                              }`}>
                                {n.type === 'error' ? <Trash2 className="h-3 w-3" /> : <Clock className="h-3 w-3" />}
                              </div>
                              <div className="flex-1 min-w-0">
                                <p className="text-sm text-gray-800 dark:text-gray-200 leading-snug">
                                  {n.message}
                                </p>
                                <p className="text-[10px] text-gray-400 mt-1 flex items-center gap-1">
                                  <Clock className="h-2 w-2" />
                                  {getTimeAgo(n.timestamp)}
                                </p>
                              </div>
                              {!n.read && (
                                <div className="h-2 w-2 bg-blue-600 rounded-full mt-1 flex-shrink-0 animate-pulse"></div>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* User Menu */}
            <div className="relative" ref={userMenuRef}>
              <button
                onClick={() => setIsUserMenuOpen(!isUserMenuOpen)}
                className="flex items-center text-gray-700 dark:text-gray-200 hover:text-blue-600 dark:hover:text-blue-400 transition-colors"
                aria-label="User menu"
              >
                <div className="h-8 w-8 rounded-full bg-blue-100 dark:bg-blue-900 flex items-center justify-center border border-blue-200 dark:border-blue-800">
                  <User className="h-5 w-5 text-blue-600 dark:text-blue-400" />
                </div>
                {user && (
                  <span className="ml-2 text-sm font-semibold hidden sm:block">
                    {user.username}
                  </span>
                )}
              </button>

              {isUserMenuOpen && (
                <div className="absolute right-0 mt-2 w-48 bg-white dark:bg-gray-900 rounded-md shadow-lg py-1 z-50 border border-gray-200 dark:border-gray-700 transition-colors duration-200">
                  {adminMenuItems.map((item) => (
                    <Link
                      key={item.name}
                      to={item.path}
                      onClick={() => setIsUserMenuOpen(false)}
                      className="block w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800"
                    >
                      {item.name}
                    </Link>
                  ))}
                  <hr className="my-1 border-gray-200 dark:border-gray-700" />
                  <button
                    onClick={handleLogout}
                    className="flex items-center w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800"
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
        <div className="md:hidden border-t border-gray-200 dark:border-gray-700 py-3">
          <div className="flex flex-col space-y-2">
            <Link
              to="/admin/products"
              className="px-3 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-gray-50 dark:hover:bg-gray-800 rounded-md transition-colors"
            >
              View Products
            </Link>
            <Link
              to="/admin/orders"
              className="px-3 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-gray-50 dark:hover:bg-gray-800 rounded-md transition-colors"
            >
              View Orders
            </Link>
            <Link
              to="/admin"
              className="px-3 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-gray-50 dark:hover:bg-gray-800 rounded-md transition-colors"
            >
              Admin Panel
            </Link>
          </div>
        </div>
      </div>
    </header>
  );
}
