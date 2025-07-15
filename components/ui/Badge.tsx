
import React from 'react';
import type { BadgeProps } from '../../types';

export const Badge: React.FC<BadgeProps> = ({ children, className, variant = 'default', ...props }) => {
  const baseStyles = "inline-flex items-center border rounded-full px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2";

  const variantStyles = {
    default: "bg-blue-600 text-white border-transparent hover:bg-blue-600/80",
    secondary: "bg-slate-200 text-slate-900 border-transparent hover:bg-slate-200/80",
    destructive: "bg-red-500 text-white border-transparent hover:bg-red-500/80",
    outline: "text-foreground", // Default outline, specific colors handled by className
  };

  return (
    <span className={`${baseStyles} ${variantStyles[variant]} ${className || ''}`} {...props}>
      {children}
    </span>
  );
};
