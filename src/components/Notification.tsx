import React, { useEffect, useState } from 'react';
import { CheckCircle, XCircle, AlertCircle, Info, X } from 'lucide-react';
import { useNotification } from '../context/NotificationContext';

export default function Notification() {
  const { notification, hideNotification } = useNotification();
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    if (notification) {
      setIsVisible(true);
    } else {
      setIsVisible(false);
    }
  }, [notification]);

  if (!notification) return null;

  const icons = {
    success: <CheckCircle className="h-5 w-5 text-green-500" />,
    error: <XCircle className="h-5 w-5 text-red-500" />,
    warning: <AlertCircle className="h-5 w-5 text-yellow-500" />,
    info: <Info className="h-5 w-5 text-blue-500" />
  };

  const bgColors = {
    success: 'bg-green-50 border-green-200',
    error: 'bg-red-50 border-red-200',
    warning: 'bg-yellow-50 border-yellow-200',
    info: 'bg-blue-50 border-blue-200'
  };

  return (
    <div 
      className={`fixed top-20 right-4 z-[9999] transition-all duration-300 transform ${
        isVisible ? 'translate-x-0 opacity-100' : 'translate-x-full opacity-0'
      }`}
    >
      <div className={`flex items-center gap-3 p-4 rounded-lg border shadow-lg ${bgColors[notification.type]} min-w-[300px]`}>
        <div className="flex-shrink-0">
          {icons[notification.type]}
        </div>
        <div className="flex-1">
          <p className="text-sm font-medium text-gray-900 leading-snug">
            {notification.message}
          </p>
        </div>
        <button 
          onClick={hideNotification}
          className="p-1 hover:bg-white hover:bg-opacity-50 rounded-full transition-colors"
        >
          <X className="h-4 w-4 text-gray-400" />
        </button>
      </div>
    </div>
  );
}
