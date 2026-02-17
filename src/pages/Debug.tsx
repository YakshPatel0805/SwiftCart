import { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useWishlist } from '../context/WishlistContext';
import { productsAPI, ordersAPI } from '../services/api';

export default function Debug() {
  const { user } = useAuth();
  const { wishlist } = useWishlist();
  const [testResults, setTestResults] = useState<string[]>([]);

  const addLog = (message: string) => {
    setTestResults(prev => [...prev, `${new Date().toLocaleTimeString()}: ${message}`]);
  };

  const testProductsAPI = async () => {
    try {
      addLog('Testing products API...');
      const products = await productsAPI.getAll();
      addLog(`✅ Products API works! Got ${products.length} products`);
      addLog(`First product ID: ${products[0]?._id || products[0]?.id}`);
    } catch (error: any) {
      addLog(`❌ Products API failed: ${error.message}`);
    }
  };

  const testWishlistAPI = async () => {
    try {
      addLog('Testing wishlist API...');
      const token = localStorage.getItem('token');
      if (!token) {
        addLog('❌ No token found - please login first');
        return;
      }
      
      const response = await fetch('http://localhost:5000/api/wishlist', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      const data = await response.json();
      addLog(`✅ Wishlist API works! Got ${data.length} items`);
    } catch (error: any) {
      addLog(`❌ Wishlist API failed: ${error.message}`);
    }
  };

  const testOrdersAPI = async () => {
    try {
      addLog('Testing orders API...');
      const orders = await ordersAPI.getAll();
      addLog(`✅ Orders API works! Got ${orders.length} orders`);
    } catch (error: any) {
      addLog(`❌ Orders API failed: ${error.message}`);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 py-12">
      <div className="max-w-4xl mx-auto px-4">
        <div className="bg-white rounded-lg shadow-md p-6">
          <h1 className="text-2xl font-bold mb-6">Debug Panel</h1>

          <div className="mb-6 p-4 bg-blue-50 rounded">
            <h2 className="font-semibold mb-2">Current Status:</h2>
            <p>User: {user ? `${user.email} (${user.role})` : 'Not logged in'}</p>
            <p>Token: {localStorage.getItem('token') ? 'Present' : 'Missing'}</p>
            <p>Wishlist items: {wishlist.length}</p>
          </div>

          <div className="space-y-4 mb-6">
            <button
              onClick={testProductsAPI}
              className="w-full bg-blue-600 text-white py-2 px-4 rounded hover:bg-blue-700"
            >
              Test Products API
            </button>
            <button
              onClick={testWishlistAPI}
              className="w-full bg-green-600 text-white py-2 px-4 rounded hover:bg-green-700"
            >
              Test Wishlist API
            </button>
            <button
              onClick={testOrdersAPI}
              className="w-full bg-purple-600 text-white py-2 px-4 rounded hover:bg-purple-700"
            >
              Test Orders API
            </button>
            <button
              onClick={() => setTestResults([])}
              className="w-full bg-gray-600 text-white py-2 px-4 rounded hover:bg-gray-700"
            >
              Clear Logs
            </button>
          </div>

          <div className="bg-gray-900 text-green-400 p-4 rounded font-mono text-sm max-h-96 overflow-y-auto">
            {testResults.length === 0 ? (
              <p>Click buttons above to test APIs...</p>
            ) : (
              testResults.map((result, index) => (
                <div key={index}>{result}</div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
