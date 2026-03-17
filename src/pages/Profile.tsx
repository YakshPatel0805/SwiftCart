import { useAuth } from '../context/AuthContext';
import { User, Shield, Mail, Crown, Edit } from 'lucide-react';
import { useState } from 'react';

export default function Profile() {
  const { user, updateProfile } = useAuth();
  const [isEditing, setIsEditing] = useState(false);
  const [editForm, setEditForm] = useState({ username: user?.username || '', email: user?.email || '' });
  const [isSaving, setIsSaving] = useState(false);

  if (!user) {
    return (
      <div className="bg-gray-50 py-12">
        <div className="mx-auto px-4 sm:px-6 lg:px-8">
          <div className="bg-white rounded-lg shadow-md p-6">
            <p className="text-gray-600">Please log in to view your profile.</p>
          </div>
        </div>
      </div>
    );
  }

  const handleSave = async () => {
    if (!editForm.username || !editForm.email) {
      alert('Please fill in all fields');
      return;
    }
    
    setIsSaving(true);
    try {
      await updateProfile(editForm.username, editForm.email);
      setIsEditing(false);
      alert('Profile updated successfully');
    } catch (error: any) {
      alert(error.message || 'Failed to update profile');
    } finally {
      setIsSaving(false);
    }
  };

  const getRoleBadge = (role?: 'user' | 'admin' | 'deliveryboy') => {
    if (role === 'admin') {
      return (
        <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-sm font-medium bg-purple-100 text-purple-800">
          <Crown className="w-4 h-4" />
          Administrator
        </span>
      );
    }
    else if (role === 'deliveryboy') {
      return (
        <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-sm font-medium bg-purple-100 text-purple-800">
          <Shield className="w-4 h-4" />
          DeliveryBoy
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-sm font-medium bg-blue-100 text-blue-800">
        <Shield className="w-4 h-4" />
        User
      </span>
    );
  };

  return (
    <div className="min-h-screen bg-gray-50 py-12">
      <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 space-y-6">
        <div className="bg-white rounded-lg shadow-md overflow-hidden">
          {/* Header */}
          <div className="bg-gradient-to-r from-blue-500 to-purple-600 px-6 py-8">
            <div className="flex items-center gap-4">
              <div className="w-20 h-20 bg-white rounded-full flex items-center justify-center">
                <User className="w-10 h-10 text-gray-600" />
              </div>
              <div className="text-white">
                <h1 className="text-2xl font-bold">{user.username}</h1>
                <p className="text-blue-100 mt-1">Member since {new Date().getFullYear()}</p>
              </div>
            </div>
          </div>

          {/* Profile Information */}
          <div className="p-6">
            <h2 className="text-xl font-semibold text-gray-900 mb-6">Profile Information</h2>
            
            <div className="space-y-4">
              {/* Username */}
              <div className="flex items-start gap-3 p-4 bg-gray-50 rounded-lg">
                <User className="w-5 h-5 text-gray-600 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm font-medium text-gray-500">Username</p>
                  {isEditing ? (
                    <input
                      type="text"
                      value={editForm.username}
                      onChange={(e) => setEditForm({ ...editForm, username: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500 mt-1"
                    />
                  ) : (
                    <p className="text-base text-gray-900 mt-1">{user.username}</p>
                  )}
                </div>
                {isEditing && (
                  <button
                    onClick={() => setEditForm({ username: user.username, email: user.email })}
                    className="text-gray-500 hover:text-gray-700"
                  >
                    <Edit className="w-5 h-5" />
                  </button>
                )}
              </div>

              {/* Email */}
              <div className="flex items-start gap-3 p-4 bg-gray-50 rounded-lg">
                <Mail className="w-5 h-5 text-gray-600 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm font-medium text-gray-500">Email Address</p>
                  {isEditing ? (
                    <input
                      type="email"
                      value={editForm.email}
                      onChange={(e) => setEditForm({ ...editForm, email: e.target.value })}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500 mt-1"
                    />
                  ) : (
                    <p className="text-base text-gray-900 mt-1">{user.email}</p>
                  )}
                </div>
                {isEditing && (
                  <button
                    onClick={() => setEditForm({ username: user.username, email: user.email })}
                    className="text-gray-500 hover:text-gray-700"
                  >
                    <Edit className="w-5 h-5" />
                  </button>
                )}
              </div>

              {/* Role */}
              <div className="flex items-start gap-3 p-4 bg-gray-50 rounded-lg">
                <Shield className="w-5 h-5 text-gray-600 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm font-medium text-gray-500">Account Role</p>
                  <div className="mt-2">
                    {getRoleBadge(user.role)}
                  </div>
                  {user.role === 'admin' && (
                    <p className="text-sm text-gray-600 mt-2">
                      You have administrative privileges to manage products and orders.
                    </p>
                  )}
                </div>
              </div>

              {/* User ID */}
              <div className="flex items-start gap-3 p-4 bg-gray-50 rounded-lg">
                <Shield className="w-5 h-5 text-gray-600 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm font-medium text-gray-500">User ID</p>
                  <p className="text-base text-gray-900 mt-1 font-mono text-sm">{user.id}</p>
                </div>
              </div>
            </div>

            {/* Edit Profile Button */}
            <div className="mt-6 flex justify-end">
              {isEditing ? (
                <>
                  <button
                    onClick={() => {
                      setIsEditing(false);
                      setEditForm({ username: user.username, email: user.email });
                    }}
                    className="mr-3 px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 font-medium"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleSave}
                    disabled={isSaving}
                    className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {isSaving ? 'Saving...' : 'Save Changes'}
                  </button>
                </>
              ) : (
                <button
                  onClick={() => {
                    setEditForm({ username: user.username, email: user.email });
                    setIsEditing(true);
                  }}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium"
                >
                  <Edit className="w-4 h-4" />
                  Edit Profile
                </button>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
