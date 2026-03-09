import React, { useState } from 'react';
import { Upload, Package, Plus } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
// import { productsAPI } from '../../services/api';

export default function AdminPanel() {
  const navigate = useNavigate();
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [uploadResult, setUploadResult] = useState<any>(null);
  const [showAddProduct, setShowAddProduct] = useState(false);
  const [addingProduct, setAddingProduct] = useState(false);
  const [productForm, setProductForm] = useState({
    name: '',
    price: '',
    image: '',
    category: '',
    description: '',
    rating: '0',
    reviews: '',
    stockQuantity: '0',
    inStock: true
  });

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
      // const result = await productsAPI.uploadCSV(file);
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
        
        const fileInput = document.getElementById('csvFile') as HTMLInputElement;
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
    const csvContent = `name,price,image,category,description,rating,reviews,inStock,stockQuantity
                        Sample T-Shirt,29.99,https://example.com/image.jpg,clothing,A comfortable cotton t-shirt,4.5,good,true,10
                        Sample Laptop,999.99,https://example.com/laptop.jpg,electronics,Powerful laptop for work,4.7,excellent choice,true, 30
                        Sample Chair,249.99,https://example.com/chair.jpg,furniture,Ergonomic office chair,4.3,reliable,true,55`;

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'products_template.csv';
    a.click();
    window.URL.revokeObjectURL(url);
  };

  const handleAddProduct = async (e: React.FormEvent) => {
    e.preventDefault();
    setAddingProduct(true);
    setMessage(null);

    try {
      const token = localStorage.getItem('token');
      const response = await fetch('http://localhost:5000/api/products', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({
          ...productForm,
          price: parseFloat(productForm.price),
          rating: parseFloat(productForm.rating),
          reviews: productForm.reviews,
        })
      });

      const data = await response.json();

      if (response.ok) {
        setMessage({ type: 'success', text: 'Product added successfully!' });
        setProductForm({
          name: '',
          price: '',
          image: '',
          category: '',
          description: '',
          rating: '0',
          reviews: '',
          stockQuantity:'0',
          inStock: true
        });
        setShowAddProduct(false);
      } else {
        setMessage({ type: 'error', text: data.message || 'Failed to add product' });
      }
    } catch (error) {
      setMessage({ type: 'error', text: 'Error adding product' });
    } finally {
      setAddingProduct(false);
    }
  };

  return (
    <div className="bg-gray-50 py-12">
      <div className="mx-auto px-4 sm:px-6 lg:px-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900">Admin Panel</h1>
          <p className="mt-2 text-gray-600">Manage products and site content</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">    
          {/* Add Single Product Section */}
          <div className="bg-white rounded-lg shadow-md p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center">
                <Plus className="h-6 w-6 text-blue-600 mr-2" />
                <h2 className="text-xl font-semibold text-gray-900">Add Single Product</h2>
              </div>
              <button
                onClick={() => setShowAddProduct(!showAddProduct)}
                className="text-blue-600 hover:text-blue-700 font-medium text-sm"
              >
                {showAddProduct ? 'Hide Form' : 'Show Form'}
              </button>
            </div>

            {showAddProduct && (
              <form onSubmit={handleAddProduct} className="space-y-4">
                <div>
                  <label  htmlFor="productName" className="block text-sm font-medium text-gray-700 mb-1">
                    Product Name *
                  </label>
                  <input
                    type="text"
                    required
                    id = "productName"
                    value={productForm.name}
                    onChange={(e) => setProductForm({ ...productForm, name: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                    placeholder="Enter product name"
                  />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label htmlFor='productPrice' className="block text-sm font-medium text-gray-700 mb-1">
                      Price *
                    </label>
                    <input
                      type="number"
                      id='productPrice'
                      required
                      value={productForm.price}
                      onChange={(e) => setProductForm({ ...productForm, price: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                      placeholder="100"
                    />
                  </div>

                  <div>
                    <label htmlFor='productCategory' className="block text-sm font-medium text-gray-700 mb-1">
                      Category *
                    </label>
                    <input
                      type="text"
                      required
                      id='productCategory'
                      value={productForm.category}
                      onChange={(e) => setProductForm({ ...productForm, category: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                      placeholder="e.g., electronics"
                    />
                  </div>
                </div>

                <div>
                  <label htmlFor='productImage' className="block text-sm font-medium text-gray-700 mb-1">
                    Image URL *
                  </label>
                  <input
                    type="url"
                    required
                    id='productImage'
                    value={productForm.image}
                    onChange={(e) => setProductForm({ ...productForm, image: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                    placeholder="https://example.com/image.jpg"
                  />
                </div>

                <div>
                  <label htmlFor='productDescription' className="block text-sm font-medium text-gray-700 mb-1">
                    Description *
                  </label>
                  <textarea
                    required
                    rows={3}
                    id='productDescription'
                    value={productForm.description}
                    onChange={(e) => setProductForm({ ...productForm, description: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                    placeholder="Enter product description"
                  />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label htmlFor='productRating' className="block text-sm font-medium text-gray-700 mb-1">
                      Rating
                    </label>
                    <input
                      type="number"
                      min="0"
                      max="5"
                      id='productRating'
                      value={productForm.rating}
                      onChange={(e) => setProductForm({ ...productForm, rating: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                    />
                  </div>

                  <div>
                    <label htmlFor='productReviews' className="block text-sm font-medium text-gray-700 mb-1">
                      Reviews
                    </label>
                    <input
                      type="text"
                      id='productReviews'
                      value={productForm.reviews}
                      onChange={(e) => setProductForm({ ...productForm, reviews: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Quantity
                    </label>
                    <input
                      type="string"
                      value={productForm.stockQuantity}
                      onChange={(e) => setProductForm({ ...productForm, stockQuantity: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                      required
                    />
                  </div>

                  <div>
                    <label htmlFor='productInStock' className="block text-sm font-medium text-gray-700 mb-1">
                      In Stock
                    </label>
                    <select
                      id='productInStock'
                      value={productForm.inStock ? 'true' : 'false'}
                      onChange={(e) => setProductForm({ ...productForm, inStock: e.target.value === 'true' })}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                    >
                      <option value="true">Yes</option>
                      <option value="false">No</option>
                    </select>
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={addingProduct}
                  className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {addingProduct ? 'Adding Product...' : 'Add Product'}
                </button>
              </form>
            )}

            {!showAddProduct && (
              <div className="text-center py-8 text-gray-500">
                <Plus className="h-12 w-12 mx-auto mb-2 text-gray-400" />
                <p>Click "Show Form" to add a single product</p>
              </div>
            )}
          </div>

          {/* CSV Upload Section */}
          <div className="bg-white rounded-lg shadow-md p-6">
            <div className="flex items-center mb-4">
              <Upload className="h-6 w-6 text-blue-600 mr-2" />
              <h2 id="upload-products" className="text-xl font-semibold text-gray-900">Upload Products</h2>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2"  htmlFor="csvFile">
                  Select CSV File
                </label>
                <input
                  id="csvFile"
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

          {/* Quick Actions */}
          <div className="bg-white rounded-lg shadow-md p-6 lg:col-span-2">
            <h2 className="text-xl font-semibold text-gray-900 mb-4">Quick Actions</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <button
                onClick={() => navigate('/admin/products')}
                className="flex items-center justify-center py-3 px-4 bg-gray-100 text-gray-700 rounded-md hover:bg-gray-200 transition-colors"
              >
                <Package className="h-5 w-5 mr-2" />
                View All Products
              </button>
              <button
                onClick={() => navigate('/admin/orders')}
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
