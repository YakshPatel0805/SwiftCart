import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { productsAPI } from '../services/api';
import { Product } from '../types';
import ProductGrid from '../components/Product/ProductGrid';
import React from 'react';

export default function SearchResults() {
  const [searchParams] = useSearchParams();
  const searchQuery = searchParams.get('q') || '';
  const [products, setProducts] = useState<Product[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadProducts();
  }, [searchQuery]);

  const loadProducts = async () => {
    try {
      setLoading(true);
      const data = await productsAPI.getAll();
      const normalizedData = data.map((p: any) => ({
        ...p,
        id: p._id || p.id
      }));

      // Filter products based on search query
      const filtered = normalizedData.filter((product: Product) => {
        const query = searchQuery.toLowerCase();
        return (
          product.name.toLowerCase().includes(query) ||
          product.description?.toLowerCase().includes(query) ||
          product.category.toLowerCase().includes(query)
        );
      });

      setProducts(filtered);
    } catch (error) {
      console.error('Error loading products:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 py-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">Loading search results...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-gray-50 py-12">
      <div className="mx-auto px-4 sm:px-6 lg:px-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">
          Search Results for "{searchQuery}"
        </h1>
        <p className="text-gray-600 mb-8">
          Found {products.length} {products.length === 1 ? 'product' : 'products'}
        </p>
        {products.length > 0 ? (
          <ProductGrid products={products} title="" />
        ) : (
          <div className="text-center py-12">
            <p className="text-gray-500 text-lg">No products found matching your search.</p>
            <p className="text-gray-400 mt-2">Try different keywords or browse our categories.</p>
          </div>
        )}
      </div>
    </div>
  );
}
