import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Package, Truck, CheckCircle, Clock, User, Phone, Mail, MapPin, ArrowLeft } from 'lucide-react';
import { ordersAPI } from '../services/api';
import PaymentDetails from '../components/Payment/PaymentDetails';
import OrderItems from '../components/Order/OrderItems';

interface TrackingInfo {
  orderId: string;
  status: string;
  createdAt: string;
  items: any[];
  total: number;
  shippingAddress: any;
  payment?: any;
  deliveryBoy: {
    name: string;
    email: string;
    mobile: string;
  } | null;
  statusHistory: {
    status: string;
    date: string;
    description: string;
  }[];
}

export default function TrackOrder() {
  const { orderId } = useParams<{ orderId: string }>();
  const navigate = useNavigate();
  const [trackingInfo, setTrackingInfo] = useState<TrackingInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (orderId) {
      loadTrackingInfo();
    }
  }, [orderId]);

  const loadTrackingInfo = async () => {
    try {
      setLoading(true);
      const data = await ordersAPI.track(orderId!);
      setTrackingInfo(data);
    } catch (error: any) {
      setError(error.message || 'Failed to load tracking information');
    } finally {
      setLoading(false);
    }
  };

  const getStatusIcon = (status: string, isActive: boolean) => {
    const iconClass = `h-6 w-6 transition-colors duration-500`;

    switch (status) {
      case 'pending':
        return <Clock className={iconClass} />;
      case 'processing':
        return <Package className={iconClass} />;
      case 'shipped':
        return <Truck className={iconClass} />;
      case 'delivered':
        return <CheckCircle className={iconClass} />;
      default:
        return <Package className={iconClass} />;
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

  const getStatusSteps = () => {
    const steps = ['pending', 'processing', 'shipped', 'delivered'];
    const currentIndex = steps.indexOf(trackingInfo?.status || 'pending');

    return steps.map((step, index) => ({
      status: step,
      label: step.charAt(0).toUpperCase() + step.slice(1),
      isActive: index <= currentIndex,
      isCompleted: index < currentIndex
    }));
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 py-12">
        <div className="w-full mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
            <p className="text-gray-600">Loading tracking information...</p>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-50 py-12">
        <div className="w-full mx-auto px-4 sm:px-6 lg:px-8">
          <div className="bg-white rounded-lg shadow-md p-6">
            <div className="text-center">
              <Package className="h-16 w-16 text-red-400 mx-auto mb-4" />
              <h2 className="text-xl font-semibold text-gray-900 mb-2">Tracking Error</h2>
              <p className="text-gray-600 mb-4">{error}</p>
              <button
                onClick={() => navigate('/orders')}
                className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors"
              >
                Back to Orders
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (!trackingInfo) {
    return null;
  }

  const statusSteps = getStatusSteps();

  return (
    <div className="min-h-screen bg-gray-50 py-12">
      <div className="w-full mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="mb-6">
          <button
            onClick={() => navigate('/orders')}
            className="flex items-center text-blue-600 hover:text-blue-700 mb-4"
          >
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Orders
          </button>
          <h1 className="text-3xl font-bold text-gray-900">Track Your Order</h1>
          <p className="text-gray-600 mt-2">Order ID: {trackingInfo.orderId}</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main Tracking Info */}
          <div className="lg:col-span-2 space-y-6">
            {/* Current Status */}
            <div className="bg-white rounded-lg shadow-md p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-semibold text-gray-900">Order Status</h2>
                <span className={`px-3 py-2 rounded-full text-sm font-medium ${getStatusColor(trackingInfo.status)}`}>
                  {trackingInfo.status.charAt(0).toUpperCase() + trackingInfo.status.slice(1)}
                </span>
              </div>

              {/* Status Progress */}
              <div className="py-8 px-4">
                <div className="flex items-center w-full">
                  {statusSteps.map((step, index) => (
                    <div key={step.status} className={`flex items-center ${index < statusSteps.length - 1 ? 'flex-1' : ''}`}>
                      {/* Icon and Label Container */}
                      <div className="flex flex-col items-center relative group">
                        <div className={`
                          relative z-10 flex items-center justify-center w-14 h-14 rounded-full border-4 transition-all duration-500 shadow-sm
                          ${step.isActive ? 'bg-blue-600 border-blue-100 text-white shadow-blue-200' : 'bg-white border-gray-50 text-gray-300'}
                          ${step.isCompleted ? 'bg-green-600 border-green-50' : ''}
                        `}>
                          {getStatusIcon(step.status, step.isActive)}
                        </div>
                        
                        <div className="absolute -bottom-10 w-32 text-center">
                          <p className={`text-xs font-bold uppercase tracking-widest transition-colors duration-500 ${step.isActive ? 'text-blue-600' : 'text-gray-400'}`}>
                            {step.label}
                          </p>
                          {step.isCompleted && (
                            <p className="text-[10px] text-green-600 font-semibold mt-0.5">Completed</p>
                          )}
                        </div>
                      </div>

                      {/* Connection Line */}
                      {index < statusSteps.length - 1 && (
                        <div className="flex-1 h-1.5 mx-2 bg-gray-100 rounded-full overflow-hidden relative">
                          <div 
                            className={`absolute top-0 left-0 h-full transition-all duration-1000 ease-in-out ${step.isCompleted ? 'bg-green-500' : 'bg-blue-600'}`}
                            style={{ width: step.isCompleted ? '100%' : (step.isActive ? '50%' : '0%') }}
                          />
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
              <div className="h-10" /> {/* Spacer for the absolute positioned labels */}
            </div>

            {/* Order Items */}
            <div className="bg-white rounded-lg shadow-md p-6">
              <h2 className="text-xl font-semibold text-gray-900 mb-4">Order Items</h2>
              <OrderItems items={trackingInfo.items} showImages={true} />
            </div>

            {/* Status History */}
            <div className="bg-white rounded-lg shadow-md p-6">
              <h2 className="text-xl font-semibold text-gray-900 mb-4">Order Timeline</h2>
              <div className="space-y-4">
                {trackingInfo.statusHistory.map((event, index) => (
                  <div key={index} className="flex items-start space-x-4">
                    <div className="flex-shrink-0">
                      <div className={`rounded-full p-2 ${event.status === trackingInfo.status ? 'bg-blue-100' : 'bg-gray-100'
                        }`}>
                        {getStatusIcon(event.status, event.status === trackingInfo.status)}
                      </div>
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-900">
                        {event.description}
                      </p>
                      <p className="text-sm text-gray-500">
                        {new Date(event.date).toLocaleString()}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* Payment Details */}
            <div>
              <PaymentDetails 
                orderId={trackingInfo.orderId}
                paymentData={trackingInfo.payment}
              />
            </div>

            {/* Delivery Information */}
            {trackingInfo.deliveryBoy && (
              <div className="bg-white rounded-lg shadow-md p-6">
                <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                  <User className="h-5 w-5 mr-2" />
                  Delivery Boy
                </h3>
                <div className="space-y-3">
                  <div className="flex items-center">
                    <User className="h-4 w-4 text-gray-400 mr-3" />
                    <span className="text-gray-900">{trackingInfo.deliveryBoy.name}</span>
                  </div>
                  <div className="flex items-center">
                    <Mail className="h-4 w-4 text-gray-400 mr-3" />
                    <span className="text-gray-600 text-sm">{trackingInfo.deliveryBoy.email}</span>
                  </div>
                  <div className="flex items-center">
                    <Phone className="h-4 w-4 text-gray-400 mr-3" />
                    <span className="text-gray-600 text-sm">{trackingInfo.deliveryBoy.mobile}</span>
                  </div>
                </div>
              </div>
            )}

            {/* Shipping Address */}
            <div className="bg-white rounded-lg shadow-md p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                <MapPin className="h-5 w-5 mr-2" />
                Shipping Address
              </h3>
              <div className="text-gray-600 space-y-1">
                <div className="flex justify-between">
                  <span className="text-gray-600">Ordered by:</span>
                  <span className="text-gray-900 font-mono text-sm">
                    {trackingInfo.shippingAddress.name}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Address:</span>
                  <span className="text-gray-900 font-mono text-sm">
                    {trackingInfo.shippingAddress.address}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">City:</span>
                  <span className="text-gray-900 font-mono text-sm">
                    {trackingInfo.shippingAddress.city}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">State:</span>
                  <span className="text-gray-900 font-mono text-sm">
                    {trackingInfo.shippingAddress.state}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Zipcode:</span>
                  <span className="text-gray-900 font-mono text-sm">
                    {trackingInfo.shippingAddress.zipcode}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Country:</span>
                  <span className="text-gray-900 font-mono text-sm">
                    {trackingInfo.shippingAddress.country}
                  </span>
                </div>
              </div>
            </div>

            {/* Order Details */}
            <div className="bg-white rounded-lg shadow-md p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Order Details</h3>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-600">Order Date:</span>
                  <span className="text-gray-900">
                    {new Date(trackingInfo.createdAt).toLocaleDateString()}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Order ID:</span>
                  <span className="text-gray-900 font-mono text-xs">
                    {trackingInfo.orderId}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}