import React from 'react';

const Skeleton = ({ className = '', variant = 'text', width, height }) => {
    const baseClasses = "bg-gray-200 animate-pulse rounded";

    const variants = {
        text: "h-4 w-full",
        circular: "rounded-full",
        rectangular: "h-32 w-full",
    };

    const style = {
        width,
        height,
    };

    return (
        <div
            className={`${baseClasses} ${variants[variant]} ${className}`}
            style={style}
        />
    );
};

export default Skeleton;
