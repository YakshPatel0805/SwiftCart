import React, { createContext, useContext, useState, useCallback, ReactNode, useEffect } from 'react';

type NotificationType = 'success' | 'error' | 'info' | 'warning';

interface NotificationItem {
  id: string;
  message: string;
  type: NotificationType;
  timestamp: string;
  read: boolean;
}

interface NotificationContextType {
  showNotification: (message: string, type?: NotificationType, persist?: boolean) => void;
  notification: { message: string, type: NotificationType } | null;
  notifications: NotificationItem[];
  unreadCount: number;
  hideNotification: () => void;
  markAllAsRead: () => void;
  clearNotifications: () => void;
}

const NotificationContext = createContext<NotificationContextType | undefined>(undefined);

const STORAGE_KEY = 'swiftcart_notifications';

export function NotificationProvider({ children }: { children: ReactNode }) {
  const [notification, setNotification] = useState<{ message: string, type: NotificationType } | null>(null);
  const [notifications, setNotifications] = useState<NotificationItem[]>(() => {
    const saved = localStorage.getItem(STORAGE_KEY);
    return saved ? JSON.parse(saved) : [];
  });

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(notifications));
  }, [notifications]);

  const hideNotification = useCallback(() => {
    setNotification(null);
  }, []);

  const showNotification = useCallback((message: string, type: NotificationType = 'success', persist: boolean = false) => {
    setNotification({ message, type });
    
    if (persist) {
      const newItem: NotificationItem = {
        id: Date.now().toString(),
        message,
        type,
        timestamp: new Date().toISOString(),
        read: false
      };

      setNotifications(prev => [newItem, ...prev].slice(0, 50)); // Keep last 50
    }

    // Auto-hide the toast after 3 seconds
    setTimeout(() => {
      hideNotification();
    }, 3000);
  }, [hideNotification]);

  const markAllAsRead = useCallback(() => {
    setNotifications(prev => prev.map(n => ({ ...n, read: true })));
  }, []);

  const clearNotifications = useCallback(() => {
    setNotifications([]);
  }, []);

  const unreadCount = notifications.filter(n => !n.read).length;

  return (
    <NotificationContext.Provider value={{ 
      showNotification, 
      notification, 
      notifications,
      unreadCount,
      hideNotification,
      markAllAsRead,
      clearNotifications
    }}>
      {children}
    </NotificationContext.Provider>
  );
}

export function useNotification() {
  const context = useContext(NotificationContext);
  if (context === undefined) {
    throw new Error('useNotification must be used within a NotificationProvider');
  }
  return context;
}
