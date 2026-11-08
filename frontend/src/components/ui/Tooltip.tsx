import React from 'react';
import { Tooltip as ArkTooltip } from '@ark-ui/react/tooltip';

interface TooltipProps {
  content: React.ReactNode;
  children: React.ReactNode;
  openDelay?: number;
  closeDelay?: number;
}

export const Tooltip: React.FC<TooltipProps> = ({
  content,
  children,
  openDelay = 200,
  closeDelay = 100,
}) => {
  return (
    <ArkTooltip.Root openDelay={openDelay} closeDelay={closeDelay}>
      <ArkTooltip.Trigger asChild>{children}</ArkTooltip.Trigger>
      <ArkTooltip.Positioner>
        <ArkTooltip.Content className="z-50 px-2.5 py-1 text-[11px] font-sans font-medium text-white bg-slate-900 rounded-md shadow-md animate-in fade-in-0 zoom-in-95 duration-100">
          <ArkTooltip.Arrow className="fill-slate-900">
            <ArkTooltip.ArrowTip />
          </ArkTooltip.Arrow>
          {content}
        </ArkTooltip.Content>
      </ArkTooltip.Positioner>
    </ArkTooltip.Root>
  );
};

