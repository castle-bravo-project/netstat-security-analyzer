
import React from 'react';
import type { AlertProps, AlertTitleProps, AlertDescriptionProps } from '../../types';
import { AlertTriangle as AlertTriangleIcon, XCircle as XCircleIcon } from 'lucide-react'; // Example icons

export const Alert: React.FC<AlertProps> = ({ children, className, variant = 'default', ...props }) => {
  const baseStyles = "relative w-full rounded-lg border p-4 [&>svg~*]:pl-7 [&>svg+div]:translate-y-[-3px] [&>svg]:absolute [&>svg]:left-4 [&>svg]:top-4";
  
  const variantStyles = {
    default: "bg-background text-foreground",
    destructive: "border-red-500/50 text-red-500 dark:border-red-500 [&>svg]:text-red-500 bg-red-50",
  };
  
  // Custom variants for yellow/warning
  const yellowVariantStyle = "border-yellow-500/50 text-yellow-700 dark:border-yellow-500 [&>svg]:text-yellow-500 bg-yellow-50";

  // Determine icon based on variant or props
  let IconComponent;
  let finalStyle = `${baseStyles} ${variantStyles[variant]}`;

  if (className?.includes('bg-yellow-50') || className?.includes('border-yellow-200')) { // Heuristic for yellow alerts
    IconComponent = AlertTriangleIcon;
    finalStyle = `${baseStyles} ${yellowVariantStyle}`;
  } else if (variant === 'destructive' || className?.includes('bg-red-50') || className?.includes('border-red-200')) {
    IconComponent = XCircleIcon;
    finalStyle = `${baseStyles} ${variantStyles.destructive}`;
  } else {
     IconComponent = AlertTriangleIcon; // Default icon
  }


  return (
    <div role="alert" className={`${finalStyle} ${className || ''}`} {...props}>
      {IconComponent && <IconComponent className="h-4 w-4" />}
      {children}
    </div>
  );
};

export const AlertTitle: React.FC<AlertTitleProps> = ({ children, className, ...props }) => (
  <h5 className={`mb-1 font-medium leading-none tracking-tight ${className || ''}`} {...props}>
    {children}
  </h5>
);

export const AlertDescription: React.FC<AlertDescriptionProps> = ({ children, className, ...props }) => (
  <div className={`text-sm [&_p]:leading-relaxed ${className || ''}`} {...props}>
    {children}
  </div>
);
