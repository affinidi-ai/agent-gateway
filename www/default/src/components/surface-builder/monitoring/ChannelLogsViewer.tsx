import React from 'react';
import LogsViewer from '../../shared/LogsViewer';

interface ChannelLogsViewerProps {
  channelConfigId: string;
  channelName?: string;
}

const ChannelLogsViewer: React.FC<ChannelLogsViewerProps> = ({ channelConfigId, channelName }) => {
  return (
    <LogsViewer
      filterPrefix={`[CHANNEL:${channelConfigId}]`}
      title="Channel Logs"
      subtitle={channelName}
    />
  );
};

export default ChannelLogsViewer;
