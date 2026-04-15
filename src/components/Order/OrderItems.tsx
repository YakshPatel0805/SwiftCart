import { OrderItemsProps } from '../../types';

export default function OrderItems({
  items,
  showImages = true
}: OrderItemsProps) {
  if (!items || items.length === 0) {
    return (
      <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
        <p className="text-sm text-yellow-800">No items found in this order</p>
      </div>
    );
  }

  // Calculate order total
  const orderTotal = items.reduce((sum, item) => {
    const price = item.productSnapshot?.price || item.product?.price || (item as any).product?.price || 0;
    return sum + (price * item.quantity);
  }, 0);

  return (
    <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
      <table className="min-w-full divide-y divide-gray-200">
        <thead className="bg-gray-50">
          <tr>
            {showImages && (
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Image
              </th>
            )}
            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Product
            </th>
            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Price
            </th>
            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Quantity
            </th>
            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Total
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-200">
          {items.map((item, index) => {
            // Handle both productSnapshot and product structures
            const productData = item.productSnapshot || item.product || (item as any).product || {};
            const productName = productData.name || 'Product Unavailable';
            const productImage = productData.image || 'https://via.placeholder.com/150';
            const productPrice = productData.price || 0;
            const lineTotal = productPrice * item.quantity;

            return (
              <tr key={index} className="hover:bg-gray-50">
                {showImages && (
                  <td className="px-4 py-3 whitespace-nowrap">
                    <img
                      src={productImage}
                      alt={productName}
                      className="h-12 w-12 rounded-md object-cover"
                      onError={(e) => {
                        (e.target as HTMLImageElement).src = 'https://via.placeholder.com/150';
                      }}
                    />
                  </td>
                )}
                <td className="px-4 py-3">
                  <span className="font-medium text-gray-900">{productName}</span>
                </td>
                <td className="px-4 py-3 text-gray-900">
                  ${productPrice.toFixed(2)}
                </td>
                <td className="px-4 py-3 text-gray-900">
                  {item.quantity}
                </td>
                <td className="px-4 py-3 font-medium text-gray-900">
                  ${lineTotal.toFixed(2)}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>

      {/* Order Total */}
      <div className="bg-gray-50 px-4 py-3 border-t border-gray-200">
        <div className="flex justify-end">
          <div className="text-right">
            <p className="text-sm text-gray-600 mb-1">Order Total:</p>
            <p className="text-xl font-bold text-gray-900">
              ${orderTotal.toFixed(2)}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
