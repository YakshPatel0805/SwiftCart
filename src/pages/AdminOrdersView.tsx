import { useState, useEffect } from 'react';
import { Package, Truck, XCircle, CheckCircle, Clock, User, Mail, MapPin, Calendar, DollarSign, Send } from 'lucide-react';
import { ordersAPI, deliveryRequestAPI } from '../services/api';
import OrderPieChart from '../components/PieChart';

export default function AdminOrdersView() {
  const [orders, setOrders] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedStatus, setSelectedStatus] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedOrder, setExpandedOrder] = useState<string | null>(null);
  const [sendingDeliveryRequestId, setSendingDeliveryRequestId] = useState<string | null>(null);

  useEffect(() => {
    loadOrders();
  }, []);

  const loadOrders = async () => {
    try {
      setLoading(true);
      const data = await ordersAPI.getAllAdmin();
      console.log('Admin orders loaded:', data);
      setOrders(data);
    } catch (error) {
      console.error('Error loading orders:', error);
    } finally {
      setLoading(false);
    }
  };

  const sendDeliveryRequest = async (orderId: string) => {
    try {
      setSendingDeliveryRequestId(orderId);
      const result = await deliveryRequestAPI.sendRequests(orderId);
      alert(`✓ ${result.message}`);
      await loadOrders();
    } catch (error: any) {
      console.error('Error sending delivery request:', error);
      const errorMessage = error.message || 'Failed to send delivery requests';
      alert(`✗ Error: ${errorMessage}\n\nPossible causes:\n- No delivery boys available\n- Order already assigned\n- Server error`);
    } finally {
      setSendingDeliveryRequestId(null);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'delivered':
        return <CheckCircle className="h-5 w-5 text-green-600" />;
      case 'shipped':
        return <Truck className="h-5 w-5 text-blue-600" />;
      case 'cancelled':
        return <XCircle className="h-5 w-5 text-red-600" />;
      case 'processing':
        return <Clock className="h-5 w-5 text-yellow-600" />;
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

  const filteredOrders = orders.filter(order => {
    const matchesStatus = selectedStatus === 'all' || order.status === selectedStatus;
    const userEmail = order.userId?.email || order.shippingAddress?.email || '';
    const userName = order.shippingAddress?.name || order.userId?.username || '';
    const matchesSearch =
      order._id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (order.userId?._id || order.userId || '').toString().toLowerCase().includes(searchQuery.toLowerCase()) ||
      userEmail.toLowerCase().includes(searchQuery.toLowerCase()) ||
      userName.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesStatus && matchesSearch;
  });

  const getOrderStats = () => {
    const deliveredOrders = orders.filter(o => o.status === 'delivered');
    return {
      total: orders.length,
      pending: orders.filter(o => o.status === 'pending').length,
      processing: orders.filter(o => o.status === 'processing').length,
      shipped: orders.filter(o => o.status === 'shipped').length,
      delivered: orders.filter(o => o.status === 'delivered').length,
      cancelled: orders.filter(o => o.status === 'cancelled').length,
      totalRevenue: deliveredOrders.reduce((sum, o) => sum + (o.total || 0), 0)
    };
  };

  const stats = getOrderStats();

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 py-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">Loading orders...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900">Order Management</h1>
          <p className="mt-2 text-gray-600">View and manage all customer orders</p>
        </div>
        
        {/* Status Cards and Graphical Visualization */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
          <div className="grid grid-cols-2 gap-4">

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
                  <p className="text-3xl font-bold text-yellow-600 mt-2">{stats.processing}</p>
                </div>
                <Clock className="h-12 w-12 text-yellow-600" />
              </div>
            </div>

            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Shipped</p>
                  <p className="text-3xl font-bold text-blue-600 mt-2">{stats.shipped}</p>
                </div>
                <Truck className="h-12 w-12 text-blue-600" />
              </div>
            </div>

            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Total Revenue</p>
                  <p className="text-2xl font-bold text-green-600 mt-2">
                    ${stats.totalRevenue.toFixed(2)}
                  </p>
                </div>
                <DollarSign className="h-12 w-12 text-green-600" />
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow-md p-6">
            <div className="flex items-center mb-4">
              <h2 className="text-xl font-semibold text-gray-900">
                Graph Analysis For Sale
              </h2>
            </div>

            <div className="h-full flex items-center justify-center text-gray-400">
              <OrderPieChart orders={orders} />
            </div>
          </div>
        </div>

        {/* Filters Section */}
        <div className="bg-white rounded-lg shadow mb-6">
          <div className="p-6">
            <div className="flex items-center mb-4">
              <Package className="h-5 w-5 text-gray-600 mr-2" />
              <h2 className="text-lg font-semibold text-gray-900">Filters</h2>
            </div>

            {/* Search Bar */}
            <div className="mb-4">
              <input
                type="text"
                placeholder="Search by Order ID, User ID, Email, or Customer Name..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>

            {/* Status Filter */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Filter by Status
              </label>
              <div className="flex flex-wrap gap-2">
                <button
                  onClick={() => setSelectedStatus('all')}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${selectedStatus === 'all'
                      ? 'bg-blue-600 text-white'
                      : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                    }`}
                >
                  All ({stats.total})
                </button>
                <button
                  onClick={() => setSelectedStatus('pending')}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${selectedStatus === 'pending'
                      ? 'bg-gray-600 text-white'
                      : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                    }`}
                >
                  Pending ({stats.pending})
                </button>
                <button
                  onClick={() => setSelectedStatus('processing')}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${selectedStatus === 'processing'
                      ? 'bg-yellow-600 text-white'
                      : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                    }`}
                >
                  Processing ({stats.processing})
                </button>
                <button
                  onClick={() => setSelectedStatus('shipped')}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${selectedStatus === 'shipped'
                      ? 'bg-blue-600 text-white'
                      : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                    }`}
                >
                  Shipped ({stats.shipped})
                </button>
                <button
                  onClick={() => setSelectedStatus('delivered')}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${selectedStatus === 'delivered'
                      ? 'bg-green-600 text-white'
                      : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                    }`}
                >
                  Delivered ({stats.delivered})
                </button>
                <button
                  onClick={() => setSelectedStatus('cancelled')}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                    selectedStatus === 'cancelled'
                      ? 'bg-red-600 text-white'
                      : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                  }`}
                >
                  Cancelled ({stats.cancelled})
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Orders List */}
        <div className="space-y-4">
          {filteredOrders.length === 0 ? (
            <div className="bg-white rounded-lg shadow p-12 text-center">
              <Package className="h-16 w-16 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-500">No orders found</p>
            </div>
          ) : (
            filteredOrders.map((order) => (
              <div key={order._id} className="bg-white rounded-lg shadow overflow-hidden">
                {/* Order Header */}
                <div
                  className="p-6 cursor-pointer hover:bg-gray-50 transition-colors"
                  onClick={() => setExpandedOrder(expandedOrder === order._id ? null : order._id)}
                >
                  <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        {getStatusIcon(order.status)}
                        <span className={`px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(order.status)}`}>
                          {order.status.charAt(0).toUpperCase() + order.status.slice(1)}
                        </span>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
                        <div className="flex items-center text-gray-600">
                          <Package className="h-4 w-4 mr-2" />
                          <span className="font-medium">Order ID:</span>
                          <span className="ml-1 font-mono">{order._id}</span>
                        </div>
                        <div className="flex items-center text-gray-600">
                          <User className="h-4 w-4 mr-2" />
                          <span className="font-medium">User ID:</span>
                          <span className="ml-1 font-mono text-xs">
                            {order.userId?._id || order.userId || 'N/A'}
                          </span>
                        </div>
                        <div className="flex items-center text-gray-600">
                          <Mail className="h-4 w-4 mr-2" />
                          <span className="font-medium">Email:</span>
                          <span className="ml-1">
                            {order.userId?.email || order.shippingAddress?.email || 'N/A'}
                          </span>
                        </div>
                        <div className="flex items-center text-gray-600">
                          <Calendar className="h-4 w-4 mr-2" />
                          <span className="font-medium">Date:</span>
                          <span className="ml-1">{new Date(order.createdAt).toLocaleDateString()}</span>
                        </div>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="text-sm text-gray-600">Total Amount</p>
                      <p className="text-2xl font-bold text-gray-900">${order.total.toFixed(2)}</p>
                    </div>
                  </div>
                </div>

                {/* Expanded Order Details */}
                {expandedOrder === order._id && (
                  <div className="border-t border-gray-200 p-6 bg-gray-50">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                      {/* Customer Information */}
                      <div>
                        <h3 className="text-lg font-semibold text-gray-900 mb-3 flex items-center">
                          <User className="h-5 w-5 mr-2" />
                          Customer Information
                        </h3>
                        <div className="bg-white rounded-lg p-4 space-y-2">
                          <div>
                            <p className="text-sm text-gray-600">Name</p>
                            <p className="font-medium">{order.shippingAddress.name}</p>
                          </div>
                          <div>
                            <p className="text-sm text-gray-600">Email</p>
                            <p className="font-medium">{order.userId?.email || order.shippingAddress?.email || 'N/A'}</p>
                          </div>
                          <div>
                            <p className="text-sm text-gray-600">User ID</p>
                            <p className="font-mono text-sm">{order.userId?._id || order.userId || 'N/A'}</p>
                          </div>
                        </div>
                      </div>

                      {/* Shipping Address */}
                      <div>
                        <h3 className="text-lg font-semibold text-gray-900 mb-3 flex items-center">
                          <MapPin className="h-5 w-5 mr-2" />
                          Shipping Address
                        </h3>
                        <div className="bg-white rounded-lg p-4">
                          <p className="font-medium">{order.shippingAddress.name}</p>
                          <p className="text-gray-600">{order.shippingAddress.address}</p>
                          <p className="text-gray-600">
                            {order.shippingAddress.city}, {order.shippingAddress.state} {order.shippingAddress.zipcode}
                          </p>
                          <p className="text-gray-600">{order.shippingAddress.country}</p>
                        </div>
                      </div>
                    </div>

                    {/* Order Items */}
                    <div>
                      <h3 className="text-lg font-semibold text-gray-900 mb-3">Order Items</h3>
                      <div className="bg-white rounded-lg overflow-hidden">
                        <table className="min-w-full divide-y divide-gray-200">
                          <thead className="bg-gray-50">
                            <tr>
                              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Product</th>
                              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Price</th>
                              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Quantity</th>
                              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Total</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-gray-200">
                            {order.items && order.items.length > 0 ? (
                              order.items.map((item: any, index: number) => {
                                const productData = item.productSnapshot || item.product || {};
                                const productName = productData.name || 'Product Unavailable';
                                const productImage = productData.image || 'https://via.placeholder.com/150';
                                const productPrice = productData.price || 0;

                                return (
                                  <tr key={index}>
                                    <td className="px-4 py-3">
                                      <div className="flex items-center">
                                        <img
                                          src={productImage}
                                          alt={productName}
                                          className="h-12 w-12 rounded-md object-cover"
                                          onError={(e) => {
                                            (e.target as HTMLImageElement).src = 'https://via.placeholder.com/150';
                                          }}
                                        />
                                        <span className="ml-3 font-medium">{productName}</span>
                                      </div>
                                    </td>
                                    <td className="px-4 py-3">${productPrice.toFixed(2)}</td>
                                    <td className="px-4 py-3">{item.quantity}</td>
                                    <td className="px-4 py-3 font-medium">
                                      ${(productPrice * item.quantity).toFixed(2)}
                                    </td>
                                  </tr>
                                );
                              })
                            ) : (
                              <tr>
                                <td colSpan={4} className="px-4 py-8 text-center text-gray-500">
                                  No items found in this order
                                </td>
                              </tr>
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>

                    {/* Order Actions */}
                    <div className="mt-6 space-y-4">
                     {/* Send Delivery Request */}
                      {order.status === 'processing' && !order.assignedDeliveryBoyId && (
                        <div>
                          <h3 className="text-lg font-semibold text-gray-900 mb-3">Delivery Management</h3>
                          <div className="bg-green-50 rounded-lg p-4 border border-green-200">
                            <p className="text-sm text-gray-600 mb-3">Send delivery requests to all available delivery boys</p>
                            <button
                              onClick={() => sendDeliveryRequest(order._id)}
                              disabled={sendingDeliveryRequestId === order._id}
                              className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:bg-gray-400 disabled:cursor-not-allowed"
                            >
                              <Send className="h-4 w-4" />
                              {sendingDeliveryRequestId === order._id ? 'Sending...' : 'Send Delivery Requests'}
                            </button>
                          </div>
                        </div>
                      )}
                      {order.assignedDeliveryBoyId && (
                        <div>
                          <h3 className="text-lg font-semibold text-gray-900 mb-3">Delivery Status</h3>
                          <div className="bg-blue-50 rounded-lg p-4 border border-blue-200">
                            <p className="text-sm text-gray-600">✓ Assigned to a delivery boy</p>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
