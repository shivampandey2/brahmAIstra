import React, { useState } from 'react';

// Simple inline-styled version with beautiful BrahmAIstra design
function App() {
  const [currentPage, setCurrentPage] = useState('home');

  const styles = {
    app: {
      backgroundColor: '#000',
      color: '#fff',
      minHeight: '100vh',
      fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, sans-serif'
    },
    nav: {
      background: 'linear-gradient(135deg, #000 0%, #1a1a1a 100%)',
      borderBottom: '1px solid rgba(236, 72, 153, 0.3)',
      padding: '1rem 2rem',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center'
    },
    logo: {
      display: 'flex',
      alignItems: 'center',
      gap: '1rem'
    },
    logoIcon: {
      width: '40px',
      height: '40px',
      background: 'linear-gradient(135deg, #f97316, #ec4899, #06b6d4)',
      borderRadius: '8px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontSize: '1.5rem',
      fontWeight: 'bold',
      color: '#000'
    },
    logoText: {
      fontSize: '1.5rem',
      fontWeight: '900',
      background: 'linear-gradient(135deg, #f97316, #ec4899, #06b6d4)',
      WebkitBackgroundClip: 'text',
      WebkitTextFillColor: 'transparent',
      backgroundClip: 'text',
      letterSpacing: '2px'
    },
    navButtons: {
      display: 'flex',
      gap: '0.5rem'
    },
    navButton: {
      padding: '0.5rem 1rem',
      background: 'transparent',
      border: '1px solid transparent',
      color: '#9ca3af',
      borderRadius: '8px',
      cursor: 'pointer',
      fontSize: '0.9rem',
      fontWeight: '600',
      transition: 'all 0.3s ease'
    },
    navButtonActive: {
      background: 'linear-gradient(135deg, rgba(249, 115, 22, 0.2), rgba(236, 72, 153, 0.2), rgba(6, 182, 212, 0.2))',
      borderColor: 'rgba(236, 72, 153, 0.5)',
      color: '#ec4899'
    },
    container: {
      padding: '4rem 2rem',
      textAlign: 'center',
      position: 'relative',
      overflow: 'hidden'
    },
    background: {
      position: 'absolute',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      background: 'radial-gradient(circle at 20% 20%, rgba(249, 115, 22, 0.1) 0%, transparent 50%), radial-gradient(circle at 80% 80%, rgba(6, 182, 212, 0.1) 0%, transparent 50%), radial-gradient(circle at 50% 50%, rgba(236, 72, 153, 0.05) 0%, transparent 70%)',
      zIndex: 0
    },
    content: {
      position: 'relative',
      zIndex: 1
    },
    comingSoon: {
      fontSize: '2.5rem',
      fontWeight: 'bold',
      marginBottom: '1rem',
      color: '#fff'
    },
    title: {
      fontSize: '4rem',
      fontWeight: '900',
      background: 'linear-gradient(135deg, #f97316, #ec4899, #06b6d4)',
      WebkitBackgroundClip: 'text',
      WebkitTextFillColor: 'transparent',
      backgroundClip: 'text',
      marginBottom: '1rem',
      letterSpacing: '3px'
    },
    subtitle: {
      fontSize: '1.2rem
