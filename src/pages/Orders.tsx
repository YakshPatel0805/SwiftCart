import { useState, useEffect, useRef } from 'react';
import { Package, CheckCircle, XCircle, Trash2, Truck, User, Phone, Mail } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { ordersAPI } from '../services/api';
import { useNotification } from '../context/NotificationContext';

export default function Orders() {
  const navigate = useNavigate();
  const [orders, setOrders] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [isCancelling, setIsCancelling] = useState(false);
  const [openDropdown, setOpenDropdown] = useState<string | null>(null);
  const { showNotification } = useNotification();
  const dropdownRefs = useRef<{ [key: string]: HTMLDivElement | null }>({});

  useEffect(() => {
    console.log('Orders page mounted, loading orders...');
    loadOrders();
  }, []);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (openDropdown) {
        const dropdownElement = dropdownRefs.current[openDropdown];
        if (dropdownElement && !dropdownElement.contains(event.target as Node)) {
          setOpenDropdown(null);
        }
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [openDropdown]);

  const loadOrders = async () => {
    try {
      console.log('Fetching orders from API...');
      const data = await ordersAPI.getAll();
      console.log('Orders received:', data);
      setOrders(data);
    } catch (error) {
      console.error('Error loading orders:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCancelOrder = async (orderId: string) => {
    if (!confirm('Are you sure you want to cancel this order?')) {
      return;
    }

    setIsCancelling(true);
    try {
      await ordersAPI.cancel(orderId);
      await loadOrders();
      setOpenDropdown(null);
      showNotification('Order cancelled successfully');
    } catch (error: any) {
      showNotification(error.message || 'Failed to cancel order', 'error');
    } finally {
      setIsCancelling(false);
    }
  };

  const handleClearOrders = async () => {
    if (!confirm('Are you sure you want to clear all your orders? This action cannot be undone.')) {
      return;
    }

    try {
      await ordersAPI.clearAll();
      await loadOrders();
      showNotification('All orders cleared successfully');
    } catch (error: any) {
      showNotification(error.message || 'Failed to clear orders', 'error');
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'delivered':
        return <CheckCircle className="h-5 w-5 text-green-600" />;
      case 'shipped':
        return <Package className="h-5 w-5 text-blue-600" />;
      case 'cancelled':
        return <XCircle className="h-5 w-5 text-red-600" />;
      default:
        return <Package className="h-5 w-5 text-gray-600" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'delivered':
        return 'bg-green-100 text-green-800';
      case 'shipped':
        return 'bg-blue-100 text-blue-800';
      case 'processing':
        return 'bg-yellow-100 text-yellow-800';
      case 'cancelled':
        return 'bg-red-100 text-red-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const canCancelOrder = (status: string) => {
    return status !== 'delivered' && status !== 'cancelled';
  };


  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 py-12">
        <div className="mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">Loading orders...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-gray-50 py-12 relative">
      {isCancelling && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-[9999]">
          <div className="bg-white p-6 rounded-lg shadow-lg text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
            <p className="text-gray-700">Cancelling order...</p>
          </div>
        </div>
      )}
      <div className="mx-auto px-4 sm:px-6 lg:px-8">
        <div className="bg-white rounded-lg shadow-md p-6">
          <h1 className="text-2xl font-bold text-gray-900 mb-6">My Orders</h1>

          {orders.length > 0 && (
            <div className="mb-4">
              <button
                onClick={handleClearOrders}
                className="flex items-center gap-2 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors text-sm"
              >
                <Trash2 className="w-4 h-4" />
                Clear All Orders
              </button>
            </div>
          )}

          {orders.length === 0 ? (
            <div className="text-center py-8">
              <Package className="h-16 w-16 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-500 mb-4">You haven't placed any orders yet.</p>
              <button
                onClick={() => navigate('/')}
                className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors"
              >
                Start Shopping
              </button>
            </div>
          ) : (
            <div className="space-y-6">
              {orders.map((order) => (
                <div key={order._id} className="border border-gray-200 rounded-lg p-6">
                  <div className="flex justify-between items-start mb-4">
                    <div>
                      <p className="text-sm text-gray-500">
                        Order ID: {order._id}
                      </p>
                      <p className="text-sm text-gray-500">
                        Placed on: {new Date(order.createdAt).toLocaleDateString()}
                      </p>
                    </div>
                    <div className="flex items-center space-x-2">
                      {getStatusIcon(order.status)}
                      <span className={`px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(order.status)}`}>
                        {order.status.charAt(0).toUpperCase() + order.status.slice(1)}
                      </span>
                    </div>
                  </div>

                  <div className="space-y-3 mb-4">
                    {order.items.map((item: any, index: number) => (
                      <div key={index} className="flex items-center space-x-4">
                        <img
                          src={item.productSnapshot?.image || item.product?.image}
                          alt={item.productSnapshot?.name || item.product?.name}
                          className="w-16 h-16 object-cover rounded-md"
                        />
                        <div className="flex-1">
                          <p className="font-medium text-gray-900">
                            {item.productSnapshot?.name || item.product?.name}
                          </p>
                          <p className="text-sm text-gray-500">Quantity: {item.quantity}</p>
                        </div>
                        <p className="font-medium text-gray-900">
                          ${((item.productSnapshot?.price || item.product?.price) * item.quantity).toFixed(2)}
                        </p>
                      </div>
                    ))}
                  </div>

                  <div className="border-t pt-4">
                    <div className="flex justify-between items-center">
                      <div>
                        <p className="text-sm text-gray-600">
                          Shipping to: {order.shippingAddress.name}
                        </p>
                        <p className="text-sm text-gray-600">
                          {order.shippingAddress.address}, {order.shippingAddress.city}
                        </p>
                      </div>
                      <div className="text-right">
                        <p className="text-sm text-gray-600">Total</p>
                        <p className="text-xl font-bold text-gray-900">${order.total.toFixed(2)}</p>
                      </div>
                    </div>

                    {/* Delivery Boy Info Banner */}
                    {order.assignedDeliveryBoyId && (
                      <div className="mt-4 bg-blue-50 border border-blue-200 rounded-lg p-4">
                        <div className="flex items-center gap-2 mb-3">
                          <Truck className="h-4 w-4 text-blue-600" />
                          <span className="text-sm font-semibold text-blue-800">Your Delivery Person</span>
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-sm">
                          <div className="flex items-center gap-2">
                            <User className="h-4 w-4 text-blue-400 flex-shrink-0" />
                            <span className="text-gray-800 font-medium">{order.assignedDeliveryBoyId.username}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <Phone className="h-4 w-4 text-blue-400 flex-shrink-0" />
                            <span className="text-gray-700">{order.assignedDeliveryBoyId.mobile || 'N/A'}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <Mail className="h-4 w-4 text-blue-400 flex-shrink-0" />
                            <span className="text-gray-600 truncate">{order.assignedDeliveryBoyId.email}</span>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Quick Track Button */}
                    <div className="mt-4 pt-4 border-t flex">
                      {canCancelOrder(order.status) && (
                        <button
                          onClick={() => handleCancelOrder(order._id)}
                        className="w-full bg-red-600 mr-5 text-white py-2 px-4 rounded-lg hover:bg-red-700 transition-colors text-sm font-medium"
                        >
                          Cancel Order
                        </button>
                      )}
                      <button
                        onClick={() => navigate(`/orders/${order._id}/track`)}
                        className="w-full bg-blue-600 ml-5 text-white py-2 px-4 rounded-lg hover:bg-blue-700 transition-colors text-sm font-medium"
                      >
                        Track This Order
                      </button>
                    </div>
                  </div>


                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
