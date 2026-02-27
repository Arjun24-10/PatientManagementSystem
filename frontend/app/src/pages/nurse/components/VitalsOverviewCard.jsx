import React from 'react';
import Card from '../../../components/common/Card';
import Badge from '../../../components/common/Badge';

const VitalsOverviewCard = ({
    alertSeverity,
    vitalsData,
    statuses,
    trends,
    normalText,
    currentPainFace,
    getStatusClasses,
    trendIcon,
    lastTimestamp,
}) => {
    const items = [{
        key: 'bp',
        label: 'Blood Pressure',
        value: vitalsData?.current ? `${vitalsData.current.bp?.systolic ?? '--'}/${vitalsData.current.bp?.diastolic ?? '--'} mmHg` : '--',
        status: statuses.bp,
        trend: trends.bpSystolic,
        helper: 'Goal < 130/85',
    }, {
        key: 'heartRate',
        label: 'Heart Rate',
        value: vitalsData?.current ? `${vitalsData.current.heartRate ?? '--'} bpm` : '--',
        status: statuses.heartRate,
        trend: trends.heartRate,
        helper: normalText.heartRate,
    }, {
        key: 'temperature',
        label: 'Temperature',
        value: vitalsData?.current ? `${vitalsData.current.temperature?.value ?? '--'} °${vitalsData.current.temperature?.unit || 'F'} (${vitalsData.current.temperature?.route || 'oral'})` : '--',
        status: statuses.temperature,
        trend: trends.temperature,
        helper: normalText.temperature,
    }, {
        key: 'respiratoryRate',
        label: 'Respiratory Rate',
        value: vitalsData?.current ? `${vitalsData.current.respiratoryRate ?? '--'} /min` : '--',
        status: statuses.respiratoryRate,
        trend: trends.respiratoryRate,
        helper: normalText.respiratoryRate,
    }, {
        key: 'oxygenSaturation',
        label: 'SpO2',
        value: vitalsData?.current ? `${vitalsData.current.oxygenSaturation ?? '--'} %` : '--',
        status: statuses.oxygenSaturation,
        trend: trends.oxygenSaturation,
        helper: normalText.oxygenSaturation,
    }, {
        key: 'painLevel',
        label: 'Pain Level',
        value: vitalsData?.current ? `${vitalsData.current.painLevel ?? '--'} / 10` : '--',
        status: statuses.painLevel,
        trend: trends.painLevel,
        helper: normalText.painLevel,
        icon: currentPainFace?.icon,
        iconLabel: currentPainFace?.label,
    }];

    const badgeType = alertSeverity === 'critical' ? 'red' : alertSeverity === 'abnormal' ? 'yellow' : 'green';

    return (
        <Card className="p-3 space-y-2.5 border border-gray-100 dark:border-slate-700 shadow-soft dark:bg-slate-800">
            <div className="flex items-start justify-between gap-2">
                <div>
                    <h3 className="text-sm font-bold text-gray-900 dark:text-slate-100">Current Vitals Overview</h3>
                    <p className="text-xs text-gray-500 dark:text-slate-400">Updated {lastTimestamp}</p>
                </div>
                <Badge type={badgeType}>
                    {alertSeverity === 'critical' ? 'Critical' : alertSeverity === 'abnormal' ? 'Monitoring' : 'Stable'}
                </Badge>
            </div>

            <div className="space-y-2">
                {items.map((item) => {
                    const StatusIcon = item.icon;
                    return (
                        <div key={item.key} className="rounded border border-gray-100 dark:border-slate-700 bg-white/80 dark:bg-slate-700/80 p-2.5 flex items-center justify-between gap-2">
                            <div>
                                <p className="text-[10px] font-semibold uppercase tracking-wide text-gray-500 dark:text-slate-400">{item.label}</p>
                                <p className="text-sm font-semibold text-gray-900 dark:text-slate-100 mt-0.5">{item.value}</p>
                                <p className="text-[10px] text-gray-400 dark:text-slate-500 mt-0.5">{item.helper}</p>
                            </div>
                            <div className="flex flex-col items-end gap-0.5">
                                <span className={`text-[10px] font-semibold ${getStatusClasses(item.status).text}`}>
                                    {item.status ? item.status.charAt(0).toUpperCase() + item.status.slice(1) : '—'}
                                </span>
                                <span className="flex items-center gap-0.5 text-[10px] text-gray-400 dark:text-slate-500">
                                    {trendIcon(item.trend)}
                                    {item.trend === 'up' ? 'Rising' : item.trend === 'down' ? 'Falling' : 'Stable'}
                                </span>
                                {StatusIcon && (
                                    <div className="flex items-center gap-0.5 text-[10px] text-gray-500 dark:text-slate-400">
                                        <StatusIcon className="w-3.5 h-3.5 text-brand-medium" aria-hidden="true" />
                                        <span>{item.iconLabel}</span>
                                    </div>
                                )}
                            </div>
                        </div>
                    );
                })}
            </div>
        </Card>
    );
};

export default VitalsOverviewCard;
