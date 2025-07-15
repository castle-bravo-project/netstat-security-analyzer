import React from 'react';
import type { InputProps } from '../../types';

export const Input: React.FC<InputProps> = ({
  className,
  variant = 'default',
  ...props
}) => {
  const baseStyles = "flex h-10 w-full rounded-md border px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50";

  const variantStyles = {
    default: "border-input bg-background",
    error: "border-red-500 bg-red-50 focus-visible:ring-red-500",
  };

  return (
    <input
      className={`${baseStyles} ${variantStyles[variant]} ${className || ''}`}
      {...props}
    />
  );
};
