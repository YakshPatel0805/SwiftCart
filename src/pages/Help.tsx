export default function Help() {
  return (
    <div className="bg-gray-50 py-12">
      <div className="mx-auto px-4 sm:px-6 lg:px-8">
        <div className="bg-white rounded-lg shadow-md p-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-6">Help Center</h1>
          <div className="space-y-6">
            <div>
              <h2 className="text-xl font-semibold text-gray-900 mb-2">Frequently Asked Questions</h2>
              <div className="space-y-4">
                <div>
                  <h3 className="font-medium text-gray-900">How do I track my order?</h3>
                  <p className="text-gray-600">You can track your order by visiting the "My Orders" section in your dashboard.</p>
                </div>
                <div>
                  <h3 className="font-medium text-gray-900">What is your return policy?</h3>
                  <p className="text-gray-600">We offer a 30-day return policy for most items. Please contact our support team for assistance.</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
