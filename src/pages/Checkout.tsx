import React, { useState } from 'react';
import { CreditCard, Truck, Lock, Smartphone, Wallet, HandCoins } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useCart } from '../context/CartContext';
import { useAuth } from '../context/AuthContext';
import { ordersAPI, paymentAPI } from '../services/api';
import { ShippingAddress, PaymentMethod } from '../types';

export default function Checkout() {
  const navigate = useNavigate();
  const { items, getTotalPrice, clearCart } = useCart();
  const { user } = useAuth();
  const [step, setStep] = useState(1);
  const [shippingAddress, setShippingAddress] = useState<ShippingAddress>({
    name: '',
    email: user?.email || '',
    address: '',
    city: '',
    state: '',
    zipcode: '',
    country: 'United States',
  });
  const [paymentMethod, setPaymentMethod] = useState<PaymentMethod>({
    type: 'credit-card',
  });

  const subtotal = getTotalPrice();
  const shipping = subtotal > 50 ? 0 : 9.99;
  const tax = subtotal * 0.08;
  const total = subtotal + shipping + tax;

  const handleShippingSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setStep(2);
  };

  const [isProcessing, setIsProcessing] = useState(false);

  const handlePaymentSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsProcessing(true);

    try {
      if (paymentMethod.type === "Account-Transfer") {
        if (!paymentMethod.accNumber || !paymentMethod.pin) {
          alert("Please enter Account Number and PIN");
          setIsProcessing(false);
          return;
        }

        // Create order with payment validation in one step
        const orderData = {
          items: items.map(item => ({
            productId: item.product.id || (item.product as any)._id,
            quantity: item.quantity
          })),
          total,
          shippingAddress,
          paymentMethod: { type: paymentMethod.type },
          accountNumber: paymentMethod.accNumber,
          pin: paymentMethod.pin
        };

        console.log("Creating order with payment", orderData);
        await paymentAPI.createWithPayment(orderData);
      } else {
        // For other payment methods, create order normally
        const orderData = {
          items: items.map(item => ({
            productId: item.product.id || (item.product as any)._id,
            quantity: item.quantity
          })),
          total,
          shippingAddress,
          paymentMethod: { type: paymentMethod.type }
        };

        console.log("Creating order", orderData);
        await ordersAPI.create(orderData);
      }

      setStep(3);
    } catch (error: any) {
      console.error("Checkout error:", error);
      console.error("Error response:", error.message, error);
      const errorMessage = error.message || error || "Payment failed";
      alert(errorMessage);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleOrderComplete = () => {
    // Clear the cart and redirect to orders
    clearCart();
    navigate('/orders');
  };

  if (!user) {
    return (
      <div className="bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <h2 className="text-2xl font-bold text-gray-900 mb-4">Please sign in to checkout</h2>
          <button
            onClick={() => navigate('/login')}
            className="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors"
          >
            Sign In
          </button>
        </div>
      </div>
    );
  }

  if (items.length === 0) {
    return (
      <div className="bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <h2 className="text-2xl font-bold text-gray-900 mb-4">Your cart is empty</h2>
          <button
            onClick={() => navigate('/')}
            className="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors"
          >
            Continue Shopping
          </button>
        </div>
      </div>
    );
  }

  if (step === 3) {
    return (
      <div className="bg-gray-50 flex items-center justify-center">
        <div className="bg-white p-8 rounded-lg shadow-md text-center max-w-md">
          <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg className="w-8 h-8 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
          </div>
          <h2 className="text-2xl font-bold text-gray-900 mb-4">Order Confirmed!</h2>
          <p className="text-gray-600 mb-6">
            Thank you for your order. You will receive a confirmation email shortly.
          </p>
          <button
            onClick={handleOrderComplete}
            className="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors"
          >
            View Orders
          </button>
        </div>
      </div>
    );
  }

  // Loading overlay
  if (isProcessing) {
    return (
      <div className="fixed inset-0 bg-gray-900 bg-opacity-50 flex items-center justify-center z-50">
        <div className="bg-white p-8 rounded-lg shadow-xl text-center max-w-sm">
          <div className="animate-spin rounded-full h-16 w-16 border-b-4 border-blue-600 mx-auto mb-6"></div>
          <h2 className="text-2xl font-bold text-gray-900 mb-2">Processing Order</h2>
          <p className="text-gray-600">Please wait while we confirm your payment and place your order...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-gray-50 py-12">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Checkout Form */}
          <div className="space-y-8">
            {/* Progress Steps */}
            <div className="flex items-center space-x-4">
              <div className={`flex items-center ${step >= 1 ? 'text-blue-600' : 'text-gray-400'}`}>
                <div className={`w-8 h-8 rounded-full flex items-center justify-center ${step >= 1 ? 'bg-blue-600 text-white' : 'bg-gray-200'}`}>
                  <Truck className="w-4 h-4" />
                </div>
                <span className="ml-2 text-sm font-medium">Shipping</span>
              </div>
              <div className={`w-8 h-0.5 ${step >= 2 ? 'bg-blue-600' : 'bg-gray-200'}`} />
              <div className={`flex items-center ${step >= 2 ? 'text-blue-600' : 'text-gray-400'}`}>
                <div className={`w-8 h-8 rounded-full flex items-center justify-center ${step >= 2 ? 'bg-blue-600 text-white' : 'bg-gray-200'}`}>
                  <CreditCard className="w-4 h-4" />
                </div>
                <span className="ml-2 text-sm font-medium">Payment</span>
              </div>
            </div>

            {/* Shipping Information */}
            {step === 1 && (
              <div className="bg-white p-6 rounded-lg shadow-md">
                <h2 className="text-xl font-semibold text-gray-900 mb-4">Shipping Information</h2>
                <form onSubmit={handleShippingSubmit} className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label htmlFor="fullName" className="block text-sm font-medium text-gray-700 mb-1">
                        Full Name
                      </label>
                      <input
                        type="text"
                        id="fullName"
                        required
                        value={shippingAddress.name}
                        onChange={(e) => setShippingAddress({ ...shippingAddress, name: e.target.value })}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                      />
                    </div>
                    <div>
                      <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">
                        Email Address
                      </label>
                      <input
                        type="email"
                        id="email"
                        required
                        value={shippingAddress.email}
                        onChange={(e) => setShippingAddress({ ...shippingAddress, email: e.target.value })}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                      />
                    </div>
                  </div>
                  <div>
                    <label htmlFor="address" className="block text-sm font-medium text-gray-700 mb-1">
                      Address
                    </label>
                    <input
                      type="text"
                      id="address"
                      required
                      value={shippingAddress.address}
                      onChange={(e) => setShippingAddress({ ...shippingAddress, address: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                    />
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="col-span-1">
                      <label htmlFor="city" className="block text-sm font-medium text-gray-700 mb-1">
                        City
                      </label>
                      <input
                        type="text"
                        id="city"
                        required
                        value={shippingAddress.city}
                        onChange={(e) => setShippingAddress({ ...shippingAddress, city: e.target.value })}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                      />
                    </div>
                    <div className="col-span-1">
                      <label htmlFor="state" className="block text-sm font-medium text-gray-700 mb-1">
                        State
                      </label>
                      <input
                        type="text"
                        id="state"
                        required
                        value={shippingAddress.state}
                        onChange={(e) => setShippingAddress({ ...shippingAddress, state: e.target.value })}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                      />
                    </div>
                    <div className="col-span-1">
                      <label htmlFor="zipcode" className="block text-sm font-medium text-gray-700 mb-1">
                        ZIP Code
                      </label>
                      <input
                        type="text"
                        id="zipcode"
                        required
                        value={shippingAddress.zipcode}
                        onChange={(e) => setShippingAddress({ ...shippingAddress, zipcode: e.target.value })}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                      />
                    </div>
                    <div className="col-span-1">
                      <label htmlFor="country" className="block text-sm font-medium text-gray-700 mb-1">
                        Country
                      </label>
                      <select
                        id="country"
                        value={shippingAddress.country}
                        onChange={(e) => setShippingAddress({ ...shippingAddress, country: e.target.value })}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                      >
                        <option value="United States">United States</option>
                        <option value="Canada">Canada</option>
                        <option value="United Kingdom">United Kingdom</option>
                        <option value="Australia">Australia</option>
                        <option value="India">India</option>
                      </select>
                    </div>
                  </div>
                  <button
                    type="submit"
                    className="w-full bg-blue-600 text-white py-3 rounded-lg hover:bg-blue-700 transition-colors font-medium"
                  >
                    Continue to Payment
                  </button>
                </form>
              </div>
            )}

            {/* Payment Information */}
            {step === 2 && (
              <div className="bg-white p-6 rounded-lg shadow-md">
                <h2 className="text-xl font-semibold text-gray-900 mb-4">Payment Information</h2>

                {/* Payment Method Selection */}
                <div className="mb-6 space-y-3">
                  <label className="flex items-center p-4 border-2 rounded-lg cursor-pointer hover:bg-gray-50 transition-colors"
                    style={{ borderColor: paymentMethod.type === 'credit-card' ? '#2563eb' : '#e5e7eb' }}>
                    <input
                      type="radio"
                      value="credit-card"
                      checked={paymentMethod.type === 'credit-card'}
                      onChange={(e) => setPaymentMethod({ type: e.target.value as any })}
                      className="text-blue-600 focus:ring-blue-500"
                    />
                    <CreditCard className="ml-3 h-5 w-5 text-gray-600" />
                    <span className="ml-3 font-medium">Credit/Debit Card</span>
                  </label>

                  <label className="flex items-center p-4 border-2 rounded-lg cursor-pointer hover:bg-gray-50 transition-colors"
                    style={{ borderColor: paymentMethod.type === 'Account-Transfer' ? '#2563eb' : '#e5e7eb' }}>
                    <input
                      type="radio"
                      value="Account-Transfer"
                      checked={paymentMethod.type === 'Account-Transfer'}
                      onChange={(e) => setPaymentMethod({ type: e.target.value as any })}
                      className="text-blue-600 focus:ring-blue-500"
                    />
                    <Wallet className="ml-3 h-5 w-5 text-gray-600" />
                    <span className="ml-3 font-medium">Account Transfer</span>
                  </label>

                  <label className="flex items-center p-4 border-2 rounded-lg cursor-pointer hover:bg-gray-50 transition-colors"
                    style={{ borderColor: paymentMethod.type === 'google-pay' ? '#2563eb' : '#e5e7eb' }}>
                    <input
                      type="radio"
                      value="google-pay"
                      checked={paymentMethod.type === 'google-pay'}
                      onChange={(e) => setPaymentMethod({ type: e.target.value as any })}
                      className="text-blue-600 focus:ring-blue-500"
                    />
                    <Smartphone className="ml-3 h-5 w-5 text-gray-600" />
                    <span className="ml-3 font-medium">Google Pay</span>
                    <span className="ml-auto text-xs bg-blue-100 text-blue-800 px-2 py-1 rounded">Fast & Secure</span>
                  </label>

                  <label className="flex items-center p-4 border-2 rounded-lg cursor-pointer hover:bg-gray-50 transition-colors"
                    style={{ borderColor: paymentMethod.type === 'cash-on-delivery' ? '#2563eb' : '#e5e7eb' }}>
                    <input
                      type="radio"
                      value="cash-on-delivery"
                      checked={paymentMethod.type === 'cash-on-delivery'}
                      onChange={(e) => setPaymentMethod({ type: e.target.value as any })}
                      className="text-blue-600 focus:ring-blue-500"
                    />
                    <HandCoins className="ml-3 h-5 w-5 text-gray-600" />
                    <span className="ml-3 font-medium">Cash on Delivery</span>
                    <span className="ml-auto text-xs bg-green-100 text-green-800 px-2 py-1 rounded">Pay Later</span>
                  </label>
                </div>

                <form onSubmit={handlePaymentSubmit} className="space-y-4">
                  {/* Credit Card Form */}
                  {paymentMethod.type === 'credit-card' && (
                    <>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">
                          Cardholder Name
                        </label>
                        <input
                          type="text"
                          required
                          value={paymentMethod.cardholderName || ''}
                          onChange={(e) => setPaymentMethod({ ...paymentMethod, cardholderName: e.target.value })}
                          className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">
                          Card Number
                        </label>
                        <input
                          type="text"
                          required
                          placeholder="1234 5678 9012 3456"
                          className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                        />
                      </div>
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-1">
                            Expiry Date
                          </label>
                          <input
                            type="text"
                            required
                            placeholder="MM/YY"
                            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-1">
                            CVV
                          </label>
                          <input
                            type="text"
                            required
                            placeholder="123"
                            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                          />
                        </div>
                      </div>
                    </>
                  )}

                  {/* Account Transfer */}
                  {paymentMethod.type === 'Account-Transfer' && (
                    <>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">
                          Account Holder Name
                        </label>
                        <input
                          type="text"
                          required
                          value={paymentMethod.accHolderName || ''}
                          onChange={(e) => setPaymentMethod({ ...paymentMethod, accHolderName: e.target.value })}
                          className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">
                          Account Number
                        </label>
                        <input
                          // type="text"
                          required
                          value={paymentMethod.accNumber || ""}
                          onChange={(e) =>
                            setPaymentMethod({ ...paymentMethod, accNumber: e.target.value })
                          }
                          placeholder="1234 5678 9012 34"
                          className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                        />
                      </div>
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-1">
                            PIN
                          </label>
                          <input
                            type="password"
                            required
                            value={paymentMethod.pin || ''}
                            onChange={(e) =>
                              setPaymentMethod({ ...paymentMethod, pin: e.target.value })
                            }
                            placeholder="1234"
                            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                          />
                        </div>
                      </div>
                    </>
                  )}

                  {/* Google Pay */}
                  {paymentMethod.type === 'google-pay' && (
                    <div className="bg-blue-50 border border-blue-200 rounded-lg p-6 text-center">
                      <Smartphone className="h-12 w-12 text-blue-600 mx-auto mb-3" />
                      <h3 className="text-lg font-semibold text-gray-900 mb-2">Pay with Google Pay</h3>
                      <p className="text-sm text-gray-600 mb-4">
                        You'll be redirected to complete your payment securely with Google Pay
                      </p>
                      <div className="flex items-center justify-center space-x-2 text-sm text-gray-500">
                        <Lock className="h-4 w-4" />
                        <span>Secured by Google</span>
                      </div>
                    </div>
                  )}

                  {/* Cash on Delivery */}
                  {paymentMethod.type === 'cash-on-delivery' && (
                    <div className="bg-green-50 border border-green-200 rounded-lg p-6">
                      <div className="flex items-start space-x-3">
                        <HandCoins className="h-6 w-6 text-green-600 mt-1" />
                        <div>
                          <h3 className="text-lg font-semibold text-gray-900 mb-2">Cash on Delivery</h3>
                          <p className="text-sm text-gray-600 mb-3">
                            Pay with cash when your order is delivered to your doorstep.
                          </p>
                          <ul className="text-sm text-gray-600 space-y-1">
                            <li>• Have exact change ready</li>
                            <li>• Payment accepted in cash only</li>
                            <li>• Delivery person will provide receipt</li>
                          </ul>
                        </div>
                      </div>
                    </div>
                  )}

                  <div className="flex items-center space-x-2 pt-2">
                    <Lock className="h-4 w-4 text-gray-500" />
                    <span className="text-sm text-gray-500">Your payment information is secure and encrypted</span>
                  </div>

                  <div className="flex space-x-4">
                    <button
                      type="button"
                      onClick={() => setStep(1)}
                      className="flex-1 border border-gray-300 text-gray-700 py-3 rounded-lg hover:bg-gray-50 transition-colors font-medium"
                    >
                      Back
                    </button>
                    <button
                      type="submit"
                      disabled={isProcessing}
                      className="flex-1 bg-blue-600 text-white py-3 rounded-lg hover:bg-blue-700 transition-colors font-medium disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {isProcessing ? 'Processing...' : paymentMethod.type === 'cash-on-delivery' ? 'Confirm Order' : 'Place Order'}
                    </button>
                  </div>
                </form>
              </div>
            )}
          </div>

          {/* Order Summary */}
          <div className="bg-white p-6 rounded-lg shadow-md h-fit">
            <h2 className="text-xl font-semibold text-gray-900 mb-4">Order Summary</h2>

            <div className="space-y-3 mb-4">
              {items.map((item) => (
                <div key={item.product.id} className="flex items-center space-x-3">
                  <img
                    src={item.product.image}
                    alt={item.product.name}
                    className="w-12 h-12 object-cover rounded-md"
                  />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-900 truncate">
                      {item.product.name}
                    </p>
                    <p className="text-sm text-gray-500">Qty: {item.quantity}</p>
                  </div>
                  <p className="text-sm font-medium text-gray-900">
                    ${(item.product.price * item.quantity).toFixed(2)}
                  </p>
                </div>
              ))}
            </div>

            <hr className="my-4" />

            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span className="text-gray-600">Subtotal</span>
                <span className="font-medium">${subtotal.toFixed(2)}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-600">Shipping</span>
                <span className="font-medium">{shipping === 0 ? 'Free' : `$${shipping.toFixed(2)}`}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-600">Tax</span>
                <span className="font-medium">${tax.toFixed(2)}</span>
              </div>
            </div>

            <hr className="my-4" />

            <div className="flex justify-between text-lg font-semibold">
              <span>Total</span>
              <span className="text-blue-600">${total.toFixed(2)}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}