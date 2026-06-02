/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        background: '#030305', // Deep space black
        surface: 'rgba(255, 255, 255, 0.03)', // Glassmorphic base
        surfaceBorder: 'rgba(255, 255, 255, 0.08)',
        neon: {
          blue: '#3b82f6',
          purple: '#8b5cf6',
          red: '#ef4444',
          green: '#10b981',
        }
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'cyber-grid': 'linear-gradient(to right, rgba(255,255,255,0.02) 1px, transparent 1px), linear-gradient(to bottom, rgba(255,255,255,0.02) 1px, transparent 1px)',
      },
      animation: {
        'glow-pulse': 'glow-pulse 3s ease-in-out infinite alternate',
        'float': 'float 6s ease-in-out infinite',
      },
      keyframes: {
        'glow-pulse': {
          '0%': { boxShadow: '0 0 15px rgba(139, 92, 246, 0.2)' },
          '100%': { boxShadow: '0 0 30px rgba(139, 92, 246, 0.6)' },
        },
        'float': {
          '0%, 100%': { transform: 'translateY(0)' },
          '50%': { transform: 'translateY(-10px)' },
        }
      }
    },
  },
  plugins: [],
}