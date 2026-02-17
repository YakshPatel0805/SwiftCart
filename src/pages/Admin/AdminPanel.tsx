import React, { useState } from 'react';
import { Upload, Package } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export default function AdminPanel() {
  const navigate = useNavigate();
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [uploadResult, setUploadResult] = useState<any>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setMessage(null);
    }
  };

  const handleUpload = async () => {
    if (!file) {
      setMessage({ type: 'error', text: 'Please select a CSV file' });
      return;
    }

    setUploading(true);
    setMessage(null);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const token = localStorage.getItem('token');
      const response = await fetch('http://localhost:5000/api/products/upload-csv', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`
        },
        body: formData
      });

      const data = await response.json();

      if (response.ok) {
        setMessage({ type: 'success', text: data.message });
        setUploadResult(data);
        setFile(null);
        
        const fileInput = document.getElementById('csv-upload') as HTMLInputElement;
        if (fileInput) fileInput.value = '';
      } else {
        setMessage({ type: 'error', text: data.message || 'Upload failed' });
      }
    } catch (error) {
      setMessage({ type: 'error', text: 'Error uploading file' });
    } finally {
      setUploading(false);
    }
  };

  const downloadTemplate = () => {
    const csvContent = `name,price,image,category,description,rating,reviews,inStock
Sample T-Shirt,29.99,https://example.com/image.jpg,clothing,A comfortable cotton t-shirt,4.5,100,true
Sample Laptop,999.99,https://example.com/laptop.jpg,electronics,Powerful laptop for work,4.7,50,true
Sample Chair,249.99,https://example.com/chair.jpg,furniture,Ergonomic office chair,4.3,75,true`;

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'products_template.csv';
    a.click();
    window.URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-gray-50 py-12">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900">Admin Panel</h1>
          <p className="mt-2 text-gray-600">Manage products and site content</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* CSV Upload Section */}
          <div className="bg-white rounded-lg shadow-md p-6">
            <div className="flex items-center mb-4">
              <Upload className="h-6 w-6 text-blue-600 mr-2" />
              <h2 className="text-xl font-semibold text-gray-900">Upload Products via CSV</h2>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Select CSV File
                </label>
                <input
                  id="csv-upload"
                  type="file"
                  accept=".csv"
                  onChange={handleFileChange}
                  className="block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100"
                />
                {file && (
                  <p className="mt-2 text-sm text-gray-600">
                    Selected: {file.name}
                  </p>
                )}
              </div>

              <button
                onClick={handleUpload}
                disabled={!file || uploading}
                className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {uploading ? 'Uploading...' : 'Upload Products'}
              </button>

              <button
                onClick={downloadTemplate}
                className="w-full bg-gray-100 text-gray-700 py-2 px-4 rounded-md hover:bg-gray-200 transition-colors"
              >
                Download CSV Template
              </button>

              {message && (
                <div
                  className={`p-4 rounded-md ${
                    message.type === 'success'
                      ? 'bg-green-50 text-green-800 border border-green-200'
                      : 'bg-red-50 text-red-800 border border-red-200'
                  }`}
                >
                  {message.text}
                </div>
              )}

              {uploadResult && uploadResult.errors && uploadResult.errors.length > 0 && (
                <div className="bg-yellow-50 border border-yellow-200 rounded-md p-4">
                  <h3 className="text-sm font-semibold text-yellow-800 mb-2">Warnings:</h3>
                  <ul className="text-sm text-yellow-700 space-y-1">
                    {uploadResult.errors.map((error: string, index: number) => (
                      <li key={index}>• {error}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>

          {/* CSV Format Guide */}
          <div className="bg-white rounded-lg shadow-md p-6">
            <div className="flex items-center mb-4">
              <Package className="h-6 w-6 text-blue-600 mr-2" />
              <h2 className="text-xl font-semibold text-gray-900">CSV Format Guide</h2>
            </div>

            <div className="space-y-4">
              <div>
                <h3 className="font-medium text-gray-900 mb-2">Required Columns:</h3>
                <ul className="text-sm text-gray-600 space-y-1">
                  <li>• <span className="font-medium">name</span> - Product name</li>
                  <li>• <span className="font-medium">price</span> - Price (number)</li>
                  <li>• <span className="font-medium">image</span> - Image URL</li>
                  <li>• <span className="font-medium">category</span> - clothing, electronics, or furniture</li>
                  <li>• <span className="font-medium">description</span> - Product description</li>
                </ul>
              </div>

              <div>
                <h3 className="font-medium text-gray-900 mb-2">Optional Columns:</h3>
                <ul className="text-sm text-gray-600 space-y-1">
                  <li>• <span className="font-medium">rating</span> - Rating (0-5, default: 0)</li>
                  <li>• <span className="font-medium">reviews</span> - Number of reviews (default: 0)</li>
                  <li>• <span className="font-medium">inStock</span> - true/false (default: true)</li>
                </ul>
              </div>

              <div className="bg-blue-50 border border-blue-200 rounded-md p-4">
                <h3 className="text-sm font-semibold text-blue-900 mb-2">Example Row:</h3>
                <code className="text-xs text-blue-800 break-all">
                  Premium T-Shirt,29.99,https://...,clothing,Comfortable shirt,4.5,100,true
                </code>
              </div>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="bg-white rounded-lg shadow-md p-6 lg:col-span-2">
            <h2 className="text-xl font-semibold text-gray-900 mb-4">Quick Actions</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <button
                onClick={() => navigate('/')}
                className="flex items-center justify-center py-3 px-4 bg-gray-100 text-gray-700 rounded-md hover:bg-gray-200 transition-colors"
              >
                <Package className="h-5 w-5 mr-2" />
                View All Products
              </button>
              <button
                onClick={() => navigate('/dashboard')}
                className="flex items-center justify-center py-3 px-4 bg-gray-100 text-gray-700 rounded-md hover:bg-gray-200 transition-colors"
              >
                Dashboard
              </button>
              <button
                onClick={() => navigate('/orders')}
                className="flex items-center justify-center py-3 px-4 bg-gray-100 text-gray-700 rounded-md hover:bg-gray-200 transition-colors"
              >
                View Orders
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
