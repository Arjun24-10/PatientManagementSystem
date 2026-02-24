module.exports = {
  darkMode: 'class', // Enable class-based dark mode
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          light: '#E3F2FD',
          medium: '#2196F3',
          deep: '#1565C0',
          dark: '#0D47A1',
        },
        admin: {
          primary: '#1E3A8A', // Deep Blue
          secondary: '#1E40AF',
          accent: '#2563EB', // Bright Blue
          success: '#16A34A', // Medical Green
          warning: '#F59E0B', // Amber
          danger: '#DC2626', // Red
          bg: '#F8FAFC', // Light Gray/White
          sidebar: '#0F172A', // Dark Navy
          surface: '#FFFFFF'
        }
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
      },
      boxShadow: {
        'soft': '0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03)',
      }
    },
  },
  plugins: [],
}
