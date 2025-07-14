import React, { useState, useEffect } from 'react';
import { Eye, EyeOff, Lock, User, Shield, LogOut, Settings, Home } from 'lucide-react';

// Type definitions
interface User {
  id: number;
  username: string;
  email: string;
  passwordHash: string;
  role: string;
  createdAt: Date;
  lastLogin: Date | null;
}

interface FormData {
  username: string;
  email: string;
  password: string;
  confirmPassword: string;
}

interface Errors {
  [key: string]: string | null;
}

// Simulated secure password hashing (in production, use bcrypt on backend)
const hashPassword = async (password) => {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + 'salt_string_2024');
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
};

// User roles and permissions
const ROLES = {
  ADMIN: 'admin',
  USER: 'user',
  MODERATOR: 'moderator'
};

const PERMISSIONS = {
  [ROLES.ADMIN]: ['read', 'write', 'delete', 'manage_users'],
  [ROLES.MODERATOR]: ['read', 'write', 'moderate'],
  [ROLES.USER]: ['read']
};

export default function SecureAuthSystem() {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [isInitialized, setIsInitialized] = useState<boolean>(false);
  const [sessionToken, setSessionToken] = useState<string | null>(null);
  const [showLogin, setShowLogin] = useState<boolean>(true);
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [formData, setFormData] = useState<FormData>({
    username: '',
    email: '',
    password: '',
    confirmPassword: ''
  });
  const [errors, setErrors] = useState<Errors>({});
  const [loading, setLoading] = useState<boolean>(false);

  // Session management and initialization
  useEffect(() => {
    const initializeApp = async () => {
      // Initialize demo user with proper password hash
      if (!isInitialized) {
        const adminPasswordHash = await hashPassword('admin123!');
        const demoUser: User = {
          id: 1,
          username: 'admin',
          email: 'admin@example.com',
          passwordHash: adminPasswordHash,
          role: ROLES.ADMIN,
          createdAt: new Date('2024-01-01'),
          lastLogin: null
        };
        setUsers([demoUser]);
        setIsInitialized(true);
      }
      
      // Check for existing session
      const storedToken = sessionStorage.getItem('authToken');
      const storedUser = sessionStorage.getItem('currentUser');
      
      if (storedToken && storedUser) {
        setSessionToken(storedToken);
        setCurrentUser(JSON.parse(storedUser));
      }
    };
    
    initializeApp();
  }, [isInitialized]);

  // Generate secure session token
  const generateSessionToken = () => {
    return crypto.randomUUID() + '-' + Date.now();
  };

  // Validate password strength
  const validatePassword = (password: string): string | null => {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (password.length < minLength) return 'Password must be at least 8 characters long';
    if (!hasUpperCase) return 'Password must contain at least one uppercase letter';
    if (!hasLowerCase) return 'Password must contain at least one lowercase letter';
    if (!hasNumbers) return 'Password must contain at least one number';
    if (!hasSpecialChar) return 'Password must contain at least one special character';
    return null;
  };

  // Validate email format
  const validateEmail = (email: string): string | null => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email) ? null : 'Please enter a valid email address';
  };

  // Handle form input changes
  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    
    // Clear errors as user types
    if (errors[name]) {
      setErrors(prev => ({
        ...prev,
        [name]: null
      }));
    }
  };

  // Handle user registration
  const handleRegister = async (e: React.MouseEvent<HTMLButtonElement>) => {
    e.preventDefault();
    setLoading(true);
    
    const newErrors: Errors = {};
    
    // Validate username
    if (!formData.username.trim()) {
      newErrors.username = 'Username is required';
    } else if (formData.username.length < 3) {
      newErrors.username = 'Username must be at least 3 characters long';
    } else if (users.find(u => u.username === formData.username)) {
      newErrors.username = 'Username already exists';
    }
    
    // Validate email
    const emailError = validateEmail(formData.email);
    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (emailError) {
      newErrors.email = emailError;
    } else if (users.find(u => u.email === formData.email)) {
      newErrors.email = 'Email already registered';
    }
    
    // Validate password
    const passwordError = validatePassword(formData.password);
    if (!formData.password) {
      newErrors.password = 'Password is required';
    } else if (passwordError) {
      newErrors.password = passwordError;
    }
    
    // Validate password confirmation
    if (formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = 'Passwords do not match';
    }
    
    setErrors(newErrors);
    
    if (Object.keys(newErrors).length === 0) {
      try {
        const hashedPassword = await hashPassword(formData.password);
        const newUser = {
          id: users.length + 1,
          username: formData.username,
          email: formData.email,
          passwordHash: hashedPassword,
          role: ROLES.USER,
          createdAt: new Date(),
          lastLogin: null
        };
        
        setUsers(prev => [...prev, newUser]);
        setFormData({ username: '', email: '', password: '', confirmPassword: '' });
        setShowLogin(true);
        
        // Success message could be shown here
        alert('Registration successful! Please log in.');
      } catch (error) {
        setErrors({ general: 'Registration failed. Please try again.' });
      }
    }
    
    setLoading(false);
  };

  // Handle user login
  const handleLogin = async (e: React.MouseEvent<HTMLButtonElement>) => {
    e.preventDefault();
    setLoading(true);
    
    const newErrors: Errors = {};
    
    if (!formData.username.trim()) {
      newErrors.username = 'Username is required';
    }
    
    if (!formData.password) {
      newErrors.password = 'Password is required';
    }
    
    setErrors(newErrors);
    
    if (Object.keys(newErrors).length === 0) {
      try {
        const hashedPassword = await hashPassword(formData.password);
        const user = users.find(u => 
          u.username === formData.username && u.passwordHash === hashedPassword
        );
        
        if (user) {
          const token = generateSessionToken();
          const updatedUser = { ...user, lastLogin: new Date() };
          
          setUsers(prev => prev.map(u => u.id === user.id ? updatedUser : u));
          setCurrentUser(updatedUser);
          setSessionToken(token);
          
          // Store in session storage (in production, use httpOnly cookies)
          sessionStorage.setItem('authToken', token);
          sessionStorage.setItem('currentUser', JSON.stringify(updatedUser));
          
          setFormData({ username: '', email: '', password: '', confirmPassword: '' });
        } else {
          setErrors({ general: 'Invalid username or password' });
        }
      } catch (error) {
        setErrors({ general: 'Login failed. Please try again.' });
      }
    }
    
    setLoading(false);
  };

  // Handle logout
  const handleLogout = () => {
    setCurrentUser(null);
    setSessionToken(null);
    sessionStorage.removeItem('authToken');
    sessionStorage.removeItem('currentUser');
    setFormData({ username: '', email: '', password: '', confirmPassword: '' });
  };

  // Check if user has permission
  const hasPermission = (permission: string): boolean => {
    if (!currentUser) return false;
    return PERMISSIONS[currentUser.role as keyof typeof PERMISSIONS]?.includes(permission) || false;
  };

  // Protected Route Component
  const ProtectedRoute: React.FC<{ children: React.ReactNode; requiredPermission?: string }> = ({ children, requiredPermission }) => {
    if (!currentUser) {
      return (
        <div className="text-center py-8">
          <Lock className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <p className="text-gray-600">Please log in to access this content.</p>
        </div>
      );
    }
    
    if (requiredPermission && !hasPermission(requiredPermission)) {
      return (
        <div className="text-center py-8">
          <Shield className="w-16 h-16 text-red-400 mx-auto mb-4" />
          <p className="text-red-600">You don't have permission to access this content.</p>
        </div>
      );
    }
    
    return <>{children}</>;
  };

  // Dashboard Component
  const Dashboard = () => (
    <div className="max-w-4xl mx-auto">
      <div className="bg-white rounded-lg shadow-md p-6 mb-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-2xl font-bold text-gray-800">Welcome, {currentUser.username}!</h2>
            <p className="text-gray-600">Role: {currentUser.role.charAt(0).toUpperCase() + currentUser.role.slice(1)}</p>
          </div>
          <button
            onClick={handleLogout}
            className="flex items-center gap-2 px-4 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors"
          >
            <LogOut className="w-4 h-4" />
            Logout
          </button>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-blue-50 p-4 rounded-lg">
            <Home className="w-8 h-8 text-blue-500 mb-2" />
            <h3 className="font-semibold text-gray-800">Dashboard</h3>
            <p className="text-sm text-gray-600">Your main dashboard</p>
          </div>
          
          {hasPermission('write') && (
            <div className="bg-green-50 p-4 rounded-lg">
              <Settings className="w-8 h-8 text-green-500 mb-2" />
              <h3 className="font-semibold text-gray-800">Content Management</h3>
              <p className="text-sm text-gray-600">Create and edit content</p>
            </div>
          )}
          
          {hasPermission('manage_users') && (
            <div className="bg-purple-50 p-4 rounded-lg">
              <User className="w-8 h-8 text-purple-500 mb-2" />
              <h3 className="font-semibold text-gray-800">User Management</h3>
              <p className="text-sm text-gray-600">Manage system users</p>
            </div>
          )}
        </div>
      </div>
      
      <div className="bg-white rounded-lg shadow-md p-6">
        <h3 className="text-lg font-semibold text-gray-800 mb-4">Your Permissions</h3>
        <div className="flex flex-wrap gap-2">
          {PERMISSIONS[currentUser.role]?.map(permission => (
            <span
              key={permission}
              className="px-3 py-1 bg-blue-100 text-blue-800 rounded-full text-sm"
            >
              {permission.replace('_', ' ').toUpperCase()}
            </span>
          ))}
        </div>
      </div>
    </div>
  );

  // If user is logged in, show dashboard
  if (currentUser && sessionToken) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-purple-600 via-blue-600 to-blue-700 py-8 px-4">
        <Dashboard />
      </div>
    );
  }

  // Authentication forms
  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-600 via-blue-600 to-blue-700 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8 bg-white rounded-xl shadow-2xl p-8">
        <div className="text-center">
          <div className="mx-auto h-16 w-16 bg-gradient-to-r from-purple-500 to-blue-500 rounded-full flex items-center justify-center">
            <Lock className="h-8 w-8 text-white" />
          </div>
          <h2 className="mt-6 text-3xl font-bold text-gray-900">
            {showLogin ? 'Sign In' : 'Create Account'}
          </h2>
          <p className="mt-2 text-sm text-gray-600">
            {showLogin ? 'Welcome back!' : 'Join us today'}
          </p>
        </div>

        <div className="mt-8 space-y-6">
          {errors.general && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
              {errors.general}
            </div>
          )}

          <div className="space-y-4">
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-gray-700">
                Username
              </label>
              <div className="mt-1 relative">
                <input
                  id="username"
                  name="username"
                  type="text"
                  required
                  value={formData.username}
                  onChange={handleInputChange}
                  className={`appearance-none relative block w-full px-3 py-2 pl-10 border ${
                    errors.username ? 'border-red-300' : 'border-gray-300'
                  } placeholder-gray-500 text-gray-900 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500`}
                  placeholder="Enter your username"
                />
                <User className="absolute left-3 top-2.5 h-5 w-5 text-gray-400" />
              </div>
              {errors.username && (
                <p className="mt-1 text-sm text-red-600">{errors.username}</p>
              )}
            </div>

            {!showLogin && (
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                  Email Address
                </label>
                <div className="mt-1">
                  <input
                    id="email"
                    name="email"
                    type="email"
                    required
                    value={formData.email}
                    onChange={handleInputChange}
                    className={`appearance-none relative block w-full px-3 py-2 border ${
                      errors.email ? 'border-red-300' : 'border-gray-300'
                    } placeholder-gray-500 text-gray-900 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500`}
                    placeholder="Enter your email"
                  />
                </div>
                {errors.email && (
                  <p className="mt-1 text-sm text-red-600">{errors.email}</p>
                )}
              </div>
            )}

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700">
                Password
              </label>
              <div className="mt-1 relative">
                <input
                  id="password"
                  name="password"
                  type={showPassword ? "text" : "password"}
                  required
                  value={formData.password}
                  onChange={handleInputChange}
                  className={`appearance-none relative block w-full px-3 py-2 pl-10 pr-10 border ${
                    errors.password ? 'border-red-300' : 'border-gray-300'
                  } placeholder-gray-500 text-gray-900 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500`}
                  placeholder="Enter your password"
                />
                <Lock className="absolute left-3 top-2.5 h-5 w-5 text-gray-400" />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-2.5 h-5 w-5 text-gray-400 hover:text-gray-600"
                >
                  {showPassword ? <EyeOff /> : <Eye />}
                </button>
              </div>
              {errors.password && (
                <p className="mt-1 text-sm text-red-600">{errors.password}</p>
              )}
            </div>

            {!showLogin && (
              <div>
                <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700">
                  Confirm Password
                </label>
                <div className="mt-1 relative">
                  <input
                    id="confirmPassword"
                    name="confirmPassword"
                    type="password"
                    required
                    value={formData.confirmPassword}
                    onChange={handleInputChange}
                    className={`appearance-none relative block w-full px-3 py-2 pl-10 border ${
                      errors.confirmPassword ? 'border-red-300' : 'border-gray-300'
                    } placeholder-gray-500 text-gray-900 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500`}
                    placeholder="Confirm your password"
                  />
                  <Lock className="absolute left-3 top-2.5 h-5 w-5 text-gray-400" />
                </div>
                {errors.confirmPassword && (
                  <p className="mt-1 text-sm text-red-600">{errors.confirmPassword}</p>
                )}
              </div>
            )}
          </div>

          <div>
            <button
              type="button"
              onClick={showLogin ? handleLogin : handleRegister}
              disabled={loading}
              className="group relative w-full flex justify-center py-3 px-4 border border-transparent text-sm font-medium rounded-lg text-white bg-gradient-to-r from-purple-500 to-blue-500 hover:from-purple-600 hover:to-blue-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200"
            >
              {loading ? 'Processing...' : showLogin ? 'Sign In' : 'Create Account'}
            </button>
          </div>

          <div className="text-center">
            <button
              type="button"
              onClick={() => {
                setShowLogin(!showLogin);
                setErrors({});
                setFormData({ username: '', email: '', password: '', confirmPassword: '' });
              }}
              className="text-sm text-blue-600 hover:text-blue-500"
            >
              {showLogin ? 'Need an account? Sign up' : 'Already have an account? Sign in'}
            </button>
          </div>
        </div>

        {showLogin && (
          <div className="mt-6 p-4 bg-gray-50 rounded-lg">
            <p className="text-xs text-gray-600 mb-2">Demo Credentials:</p>
            <p className="text-xs text-gray-500">Username: <span className="font-mono font-semibold">admin</span></p>
            <p className="text-xs text-gray-500">Password: <span className="font-mono font-semibold">admin123!</span></p>
          </div>
        )}
      </div>
    </div>
  );
}