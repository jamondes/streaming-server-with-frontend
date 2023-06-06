import React from 'react';
import { Typography } from '@mui/material';
import { makeStyles } from 'tss-react/mui';
import ReactPlayer from 'react-player';
import { useAuth } from './auth';
import { ROUTES } from "./constants";

const useStyles = makeStyles((theme) => ({
  videoContainer: {
    maxWidth: '800px',
    margin: '0 auto',
    marginTop: theme.spacing(4),
  },
}));

const VideoStream = () => {
  const classes = useStyles();
  const auth = useAuth();
  const videoUrl = ROUTES.videoStream;

  return (
    <div>
      <Typography variant="h4" align="center" gutterBottom>
        Video Streaming
      </Typography>
      <div className={classes.videoContainer}>
        <ReactPlayer 
          config={{
            file: {
              forceHLS: true,
              hlsOptions: {
                xhrSetup: function (xhr, url) {
                  xhr.open("GET", url, true);
                  xhr.setRequestHeader(
                    "Authorization",
                    `Bearer ${auth.user?.token}`
                  );
                },
              },
            },
          }}
          url={videoUrl} 
          controls 
          width="100%" 
          height="auto" 
        />
      </div>
    </div>
  );
};

export default VideoStream;
