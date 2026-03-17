import { useState, useEffect } from 'react';
import { Package, Truck, CheckCircle, Clock, AlertCircle, Check, X, RefreshCw } from 'lucide-react';
import { ordersAPI, deliveryRequestAPI } from '../services/api';

interface DeliveryRequest {
  _id: string;
  orderId: {
    _id: string;
    total: number;
    status: string;
    shippingAddress: {
      name: string;
      email: string;
      address: string;
      city: string;
      state: string;
      zipcode: string;
      country: string;
    };
    items: any[];
  };
  status: 'pending' | 'accepted' | 'rejected' | 'completed';
  requestedAt: string;
  respondedAt?: string;
}

interface OrderItem {
  product: {
    _id: string;
    name: string;
    image: string;
  };
  productSnapshot: {
    name: string;
    price: number;
    image: string;
  };
  quantity: number;
}

interface Order {
  _id: string;
  userId: {
    email: string;
    username: string;
  };
  items: OrderItem[];
  total: number;
  status: 'pending' | 'processing' | 'shipped' | 'delivered' | 'cancelled';
  shippingAddress: {
    name: string;
    email: string;
    address: string;
    city: string;
    state: string;
    zipcode: string;
    country: string;
  };
  createdAt: string;
}

export default function DeliveryBoyDashboard() {
  const [orders, setOrders] = useState<Order[]>([]);
  const [requests, setRequests] = useState<DeliveryRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [updatingOrderId, setUpdatingOrderId] = useState<string | null>(null);
  const [respondingRequestId, setRespondingRequestId] = useState<string | null>(null);
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [activeTab, setActiveTab] = useState<'requests' | 'orders'>('requests');

  useEffect(() => {
    loadData();
    // Auto-refresh every 10 seconds
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, []);

  const loadData = async () => {
    try {
      if (!refreshing) setLoading(true);
      
      console.log('📥 Loading orders...');
      const ordersData = await ordersAPI.getDeliveryBoyOrders();
      console.log('✓ Orders loaded:', ordersData.length);
      
      console.log('📥 Loading pending requests...');
      const requestsData = await deliveryRequestAPI.getPendingRequests();
      console.log('✓ Requests loaded:', requestsData.length);
      
      setOrders(ordersData);
      setRequests(requestsData);
      console.log('✓ Dashboard data loaded:', { orders: ordersData.length, requests: requestsData.length });
    } catch (error: any) {
      console.error('❌ Error loading data:', error);
      console.error('Error message:', error.message);
      console.error('Error details:', error);
      alert(`Failed to load data: ${error.message}`);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    await loadData();
  };

  const handleAcceptRequest = async (requestId: string) => {
    try {
      setRespondingRequestId(requestId);
      await deliveryRequestAPI.acceptRequest(requestId);
      alert('Delivery request accepted! You can now update the order status.');
      await loadData();
    } catch (error) {
      console.error('Error accepting request:', error);
      alert('Failed to accept request');
    } finally {
      setRespondingRequestId(null);
    }
  };

  const handleRejectRequest = async (requestId: string) => {
    try {
      setRespondingRequestId(requestId);
      await deliveryRequestAPI.rejectRequest(requestId);
      alert('Delivery request rejected');
      await loadData();
    } catch (error) {
      console.error('Error rejecting request:', error);
      alert('Failed to reject request');
    } finally {
      setRespondingRequestId(null);
    }
  };

  const handleStatusUpdate = async (orderId: string, newStatus: 'shipped' | 'delivered') => {
    try {
      setUpdatingOrderId(orderId);
      await ordersAPI.updateDeliveryBoyOrderStatus(orderId, newStatus);
      await loadData();
      alert(`Order status updated to ${newStatus}`);
    } catch (error) {
      console.error('Error updating order status:', error);
      alert('Failed to update order status');
    } finally {
      setUpdatingOrderId(null);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'pending':
        return 'bg-yellow-100 text-yellow-800';
      case 'processing':
        return 'bg-blue-100 text-blue-800';
      case 'shipped':
        return 'bg-purple-100 text-purple-800';
      case 'delivered':
        return 'bg-green-100 text-green-800';
      case 'cancelled':
        return 'bg-red-100 text-red-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'pending':
        return <Clock className="h-4 w-4" />;
      case 'processing':
        return <AlertCircle className="h-4 w-4" />;
      case 'shipped':
        return <Truck className="h-4 w-4" />;
      case 'delivered':
        return <CheckCircle className="h-4 w-4" />;
      default:
        return <Package className="h-4 w-4" />;
    }
  };

  const filteredOrders = filterStatus === 'all' 
    ? orders 
    : orders.filter(order => order.status === filterStatus);

  const stats = {
    total: orders.length,
    processing: orders.filter(o => o.status === 'processing').length,
    shipped: orders.filter(o => o.status === 'shipped').length,
    delivered: orders.filter(o => o.status === 'delivered').length,
    pendingRequests: requests.filter(r => r.status === 'pending').length
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 py-12">
        <div className="mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">Loading...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-gray-900">Delivery Dashboard</h1>
              <p className="mt-2 text-gray-600">Manage delivery requests and track orders</p>
            </div>
            <button
              onClick={handleRefresh}
              disabled={refreshing}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-gray-400"
              title="Refresh data"
            >
              <RefreshCw className={`h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />
              {refreshing ? 'Refreshing...' : 'Refresh'}
            </button>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-8">
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Pending Requests</p>
                <p className="text-3xl font-bold text-orange-600 mt-2">{stats.pendingRequests}</p>
              </div>
              <AlertCircle className="h-12 w-12 text-orange-400" />
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Total Orders</p>
                <p className="text-3xl font-bold text-gray-900 mt-2">{stats.total}</p>
              </div>
              <Package className="h-12 w-12 text-blue-600" />
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Processing</p>
                <p className="text-3xl font-bold text-blue-600 mt-2">{stats.processing}</p>
              </div>
              <AlertCircle className="h-12 w-12 text-blue-400" />
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Shipped</p>
                <p className="text-3xl font-bold text-purple-600 mt-2">{stats.shipped}</p>
              </div>
              <Truck className="h-12 w-12 text-purple-400" />
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Delivered</p>
                <p className="text-3xl font-bold text-green-600 mt-2">{stats.delivered}</p>
              </div>
              <CheckCircle className="h-12 w-12 text-green-400" />
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="bg-white rounded-lg shadow mb-6">
          <div className="flex border-b border-gray-200">
            <button
              onClick={() => setActiveTab('requests')}
              className={`flex-1 px-6 py-4 text-center font-medium transition-colors ${
                activeTab === 'requests'
                  ? 'text-blue-600 border-b-2 border-blue-600'
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              Delivery Requests ({stats.pendingRequests})
            </button>
            <button
              onClick={() => setActiveTab('orders')}
              className={`flex-1 px-6 py-4 text-center font-medium transition-colors ${
                activeTab === 'orders'
                  ? 'text-blue-600 border-b-2 border-blue-600'
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              My Orders ({stats.total})
            </button>
          </div>
        </div>

        {/* Delivery Requests Tab */}
        {activeTab === 'requests' && (
          <div className="bg-white rounded-lg shadow overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-gray-900">
                Pending Delivery Requests
                <span className="text-gray-500 font-normal ml-2">({requests.filter(r => r.status === 'pending').length})</span>
              </h2>
            </div>

            {requests.filter(r => r.status === 'pending').length === 0 ? (
              <div className="text-center py-12">
                <Package className="h-16 w-16 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-500">No pending delivery requests</p>
              </div>
            ) : (
              <div className="divide-y divide-gray-200">
                {requests.filter(r => r.status === 'pending').map((request) => (
                  <div key={request._id} className="p-6 hover:bg-gray-50">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div>
                        <h3 className="text-lg font-semibold text-gray-900 mb-4">
                          Order #{request.orderId._id.slice(-8).toUpperCase()}
                        </h3>
                        <div className="space-y-2">
                          <p><strong>Customer:</strong> {request.orderId.shippingAddress.name}</p>
                          <p><strong>Email:</strong> {request.orderId.shippingAddress.email}</p>
                          <p><strong>Total:</strong> ${request.orderId.total.toFixed(2)}</p>
                          <p><strong>Items:</strong> {request.orderId.items.length}</p>
                        </div>
                      </div>
                      <div>
                        <h4 className="font-semibold text-gray-900 mb-2">Delivery Address</h4>
                        <p className="text-sm text-gray-600">
                          {request.orderId.shippingAddress.address}<br />
                          {request.orderId.shippingAddress.city}, {request.orderId.shippingAddress.state} {request.orderId.shippingAddress.zipcode}<br />
                          {request.orderId.shippingAddress.country}
                        </p>
                        <div className="mt-4 flex gap-3">
                          <button
                            onClick={() => handleAcceptRequest(request._id)}
                            disabled={respondingRequestId === request._id}
                            className="flex-1 bg-green-600 text-white py-2 rounded-lg hover:bg-green-700 disabled:bg-gray-400 flex items-center justify-center gap-2"
                          >
                            <Check className="h-4 w-4" />
                            {respondingRequestId === request._id ? 'Accepting...' : 'Accept'}
                          </button>
                          <button
                            onClick={() => handleRejectRequest(request._id)}
                            disabled={respondingRequestId === request._id}
                            className="flex-1 bg-red-600 text-white py-2 rounded-lg hover:bg-red-700 disabled:bg-gray-400 flex items-center justify-center gap-2"
                          >
                            <X className="h-4 w-4" />
                            {respondingRequestId === request._id ? 'Rejecting...' : 'Reject'}
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Orders Tab */}
        {activeTab === 'orders' && (
          <>
            {/* Filter */}
            <div className="bg-white rounded-lg shadow mb-6 p-6">
              <label className="block text-sm font-medium text-gray-700 mb-3">
                Filter by Status
              </label>
              <div className="flex flex-wrap gap-2">
                {['all', 'processing', 'shipped', 'delivered'].map(status => (
                  <button
                    key={status}
                    onClick={() => setFilterStatus(status)}
                    className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors capitalize ${
                      filterStatus === status
                        ? 'bg-blue-600 text-white'
                        : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                    }`}
                  >
                    {status}
                  </button>
                ))}
              </div>
            </div>

            {/* Orders Table */}
            <div className="bg-white rounded-lg shadow overflow-hidden">
              <div className="px-6 py-4 border-b border-gray-200">
                <h2 className="text-lg font-semibold text-gray-900">
                  My Orders
                  <span className="text-gray-500 font-normal ml-2">({filteredOrders.length})</span>
                </h2>
              </div>

              {filteredOrders.length === 0 ? (
                <div className="text-center py-12">
                  <Package className="h-16 w-16 text-gray-400 mx-auto mb-4" />
                  <p className="text-gray-500">No orders found</p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Order ID
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Customer
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Address
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Total
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Status
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Actions
                        </th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {filteredOrders.map((order) => (
                        <tr key={order._id} className="hover:bg-gray-50">
                          <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                            {order._id.slice(-8).toUpperCase()}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm font-medium text-gray-900">{order.shippingAddress.name}</div>
                            <div className="text-sm text-gray-500">{order.shippingAddress.email}</div>
                          </td>
                          <td className="px-6 py-4">
                            <div className="text-sm text-gray-900">
                              {order.shippingAddress.address}
                            </div>
                            <div className="text-sm text-gray-500">
                              {order.shippingAddress.city}, {order.shippingAddress.state}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                            ${order.total.toFixed(2)}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className={`px-3 py-1 inline-flex items-center gap-1 text-xs leading-5 font-semibold rounded-full ${getStatusColor(order.status)}`}>
                              {getStatusIcon(order.status)}
                              {order.status.charAt(0).toUpperCase() + order.status.slice(1)}
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                            {(order.status === 'processing' || order.status === 'shipped') && (
                              <div className="flex gap-2">
                                {order.status === 'processing' && (
                                  <button
                                    onClick={() => handleStatusUpdate(order._id, 'shipped')}
                                    disabled={updatingOrderId === order._id}
                                    className="text-blue-600 hover:text-blue-900 disabled:opacity-50"
                                    title="Mark as shipped"
                                  >
                                    {updatingOrderId === order._id ? 'Updating...' : 'Ship'}
                                  </button>
                                )}
                                {order.status === 'shipped' && (
                                  <button
                                    onClick={() => handleStatusUpdate(order._id, 'delivered')}
                                    disabled={updatingOrderId === order._id}
                                    className="text-green-600 hover:text-green-900 disabled:opacity-50"
                                    title="Mark as delivered"
                                  >
                                    {updatingOrderId === order._id ? 'Updating...' : 'Deliver'}
                                  </button>
                                )}
                              </div>
                            )}
                            {order.status === 'delivered' && (
                              <span className="text-green-600 font-semibold">✓ Delivered</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
