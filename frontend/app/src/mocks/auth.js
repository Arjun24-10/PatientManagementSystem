// Mock authentication data for development and testing
// These credentials can be used to test different user roles and 2FA scenarios

export const mockUsers = [
  {
    id: 1,
    email: "doctor@hospital.com",
    password: "doctor123456!", // 12+ chars for NIST compliance
    role: "doctor",
    name: "Dr. Sarah Johnson",
    twoFactorEnabled: true,
    phone: "***-***-1234",
    maskedEmail: "d***r@hospital.com"
  },
  {
    id: 2,
    email: "nurse@hospital.com",
    password: "nurse1234567!", // 12+ chars
    role: "nurse",
    name: "Nurse Jennifer Martinez",
    twoFactorEnabled: true,
    phone: "***-***-5678",
    maskedEmail: "n***e@hospital.com"
  },
  {
    id: 3,
    email: "patient@hospital.com",
    password: "patient12345!", // 12+ chars
    role: "patient",
    name: "John Smith",
    twoFactorEnabled: false,
    phone: null,
    maskedEmail: null
  },
  {
    id: 4,
    email: "admin@hospital.com",
    password: "admin1234567!", // 12+ chars
    role: "admin",
    name: "Admin User",
    twoFactorEnabled: true,
    phone: "***-***-9999",
    maskedEmail: "a***n@hospital.com"
  },
  {
    id: 5,
    email: "lab@hospital.com",
    password: "labtech12345!", // 12+ chars
    role: "lab_technician",
    name: "Mike Lab Technician",
    twoFactorEnabled: true,
    phone: "***-***-4321",
    maskedEmail: "l***b@hospital.com"
  }
];

// Mock OTP codes for demo purposes
export const MOCK_OTP = "123456";
export const MOCK_BACKUP_CODES = [
  "ABCD-EFGH-1234-5678",
  "IJKL-MNOP-9012-3456",
  "QRST-UVWX-7890-1234"
];

// OTP expiry time in milliseconds (10 minutes)
export const OTP_EXPIRY_MS = 10 * 60 * 1000;

// Resend cooldown in seconds
export const RESEND_COOLDOWN_SECONDS = 60;

// Max verification attempts
export const MAX_VERIFICATION_ATTEMPTS = 3;

// Lockout duration after max failed attempts (15 minutes)
export const LOCKOUT_DURATION_MS = 15 * 60 * 1000;

/**
 * Mock login handler - simulates backend authentication
 * @param {string} email - User email
 * @param {string} password - User password
 * @param {boolean} rememberMe - Remember me preference
 * @returns {Object} Login result
 */
export const mockLogin = async (email, password, rememberMe = false) => {
  // Simulate network delay
  await new Promise(resolve => setTimeout(resolve, 800));

  const user = mockUsers.find(
    u => u.email.toLowerCase() === email.toLowerCase() && u.password === password
  );

  if (!user) {
    return {
      success: false,
      error: "Invalid email or password. Please try again."
    };
  }

  if (user.twoFactorEnabled) {
    // User needs 2FA verification
    return {
      success: true,
      requiresTwoFactor: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        maskedEmail: user.maskedEmail,
        maskedPhone: user.phone
      },
      tempToken: `temp_${user.id}_${Date.now()}` // Temporary token for 2FA flow
    };
  }

  // Direct login (no 2FA)
  if (rememberMe) {
    localStorage.setItem('authToken', `token_${user.id}_${Date.now()}`);
  }

  return {
    success: true,
    requiresTwoFactor: false,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role
    },
    redirectTo: `/dashboard/${user.role === 'lab_technician' ? 'lab' : user.role}`
  };
};

/**
 * Mock OTP verification handler
 * @param {string} code - 6-digit OTP code
 * @param {string} tempToken - Temporary token from login
 * @returns {Object} Verification result
 */
export const mockVerifyOTP = async (code, tempToken) => {
  // Simulate network delay
  await new Promise(resolve => setTimeout(resolve, 1000));

  if (code === MOCK_OTP) {
    // Extract user ID from temp token
    const userId = parseInt(tempToken.split('_')[1]);
    const user = mockUsers.find(u => u.id === userId);

    if (user) {
      return {
        success: true,
        message: "Verification successful",
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role
        },
        redirectTo: `/dashboard/${user.role === 'lab_technician' ? 'lab' : user.role}`
      };
    }
  }

  return {
    success: false,
    error: "Invalid verification code. Please try again.",
    attemptsRemaining: 2
  };
};

/**
 * Mock backup code verification handler
 * @param {string} backupCode - Backup code
 * @param {string} tempToken - Temporary token from login
 * @returns {Object} Verification result
 */
export const mockVerifyBackupCode = async (backupCode, tempToken) => {
  // Simulate network delay
  await new Promise(resolve => setTimeout(resolve, 1000));

  const normalizedCode = backupCode.toUpperCase().replace(/\s/g, '');
  const isValid = MOCK_BACKUP_CODES.some(
    code => code.replace(/-/g, '') === normalizedCode.replace(/-/g, '')
  );

  if (isValid) {
    const userId = parseInt(tempToken.split('_')[1]);
    const user = mockUsers.find(u => u.id === userId);

    if (user) {
      return {
        success: true,
        message: "Backup code verified successfully",
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role
        },
        redirectTo: `/dashboard/${user.role === 'lab_technician' ? 'lab' : user.role}`
      };
    }
  }

  return {
    success: false,
    error: "Invalid backup code. Please try again.",
    attemptsRemaining: 2
  };
};

/**
 * Mock resend OTP handler
 * @param {string} tempToken - Temporary token from login
 * @returns {Object} Resend result
 */
export const mockResendOTP = async (tempToken) => {
  // Simulate network delay
  await new Promise(resolve => setTimeout(resolve, 500));

  console.log("New OTP sent for token:", tempToken);
  
  return {
    success: true,
    message: "A new verification code has been sent to your device."
  };
};
