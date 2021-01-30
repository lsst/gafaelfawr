import formatDistanceToNow from 'date-fns/formatDistanceToNow';
import fromUnixTime from 'date-fns/fromUnixTime';
import PropTypes from 'prop-types';
import React from 'react';

export default function Timestamp({ timestamp, past }) {
  if (!timestamp) return <em>never</em>;
  const date = fromUnixTime(timestamp);
  const relative = formatDistanceToNow(date, { addSuffix: past });
  const absolute = date.toISOString().replace(/\.0+Z$/, 'Z');
  return (
    <time title={absolute} dateTime={absolute}>
      {relative}
    </time>
  );
}
Timestamp.propTypes = {
  timestamp: PropTypes.number.isRequired,
  past: PropTypes.bool.isRequired,
};
