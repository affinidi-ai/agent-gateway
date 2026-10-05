/**
 * Truncates a string by showing the first `top` characters, ellipses, and the last `tail` characters.
 * If the string is shorter than top + tail + 3 (for ellipses), returns the original string.
 *
 * @param str - The input string to truncate
 * @param top - Number of characters to show at the beginning
 * @param tail - Number of characters to show at the end
 * @returns The truncated string with ellipses in the middle
 *
 * @example
 * topAndTail("did:web:example.com:very:long:identifier:path", 16, 24)
 * // Returns: "did:web:...her:path"
 */
export function topAndTail(str: string, top: number, tail: number): string {
  // If string is shorter than what we'd show with ellipses, return original
  if (str.length <= top + tail + 3) {
    return str;
  }

  const beginning = str.substring(0, top);
  const ending = str.substring(str.length - tail);

  return `${beginning}...${ending}`;
}

/**
 * Formats a date object into a consistent string format.
 *
 * @param date - The date to format (Date object or string that can be parsed as a date)
 * @param includeTime - Whether to include the time in the output
 * @returns Formatted date string
 *
 * @example
 * formatDateTime(new Date('2025-12-19T10:50:00'), true)
 * // Returns: "December 19, 2025 at 10:50"
 *
 * formatDateTime(new Date('2025-12-19T10:50:00'), false)
 * // Returns: "December 19, 2025"
 */
export function formatDateTime(
  date: Date | string | undefined | null,
  includeTime: boolean = false
): string {
  if (date == null) {
    return '-';
  }
  const dateObj = typeof date === 'string' ? new Date(date) : date;

  if (isNaN(dateObj.getTime())) {
    return 'Invalid date';
  }

  const options: Intl.DateTimeFormatOptions = {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  };

  if (includeTime) {
    options.hour = '2-digit';
    options.minute = '2-digit';
    options.hour12 = false;
  }

  if (includeTime) {
    const datePart = dateObj.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
    const timePart = dateObj.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    });
    return `${datePart} at ${timePart}`;
  }

  return dateObj.toLocaleDateString('en-US', options);
}

/**
 * Formats a date object to show only the time in 24-hour format.
 * Useful for chart labels and compact displays.
 * Always displays in the user's local timezone.
 *
 * @param date - The date to format (Date object or string that can be parsed as a date)
 * @returns Formatted time string in HH:MM format
 *
 * @example
 * formatTime(new Date('2025-12-19T10:50:00'))
 * // Returns: "10:50"
 */
export function formatTime(date: Date | string): string {
  const dateObj = typeof date === 'string' ? new Date(date) : date;

  // Check if date is valid
  if (isNaN(dateObj.getTime())) {
    return 'Invalid time';
  }

  // Use undefined locale to use browser's default locale/timezone
  const options: Intl.DateTimeFormatOptions = {
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
    timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone, // Explicit local timezone
  };

  return dateObj.toLocaleTimeString(undefined, options);
}

/**
 * Returns a human-readable "time ago" string for a given date.
 * For dates within the last 24 hours, shows relative time ("5 minutes ago", "3 hours ago").
 * For dates older than 24 hours, shows formatted date with time.
 *
 * @param date - The date to compare against now (Date object or string that can be parsed as a date)
 * @param numericDates - Whether to use numeric dates (e.g., "1 day ago") or text (e.g., "Yesterday"). Defaults to true.
 * @returns A human-readable string representing how long ago the date was
 *
 * @example
 * timeAgo(new Date(Date.now() - 1000 * 60 * 5))
 * // Returns: "5 minutes ago"
 *
 * timeAgo(new Date(Date.now() - 1000 * 60 * 60 * 3))
 * // Returns: "3 hours ago"
 *
 * timeAgo(new Date(Date.now() - 1000 * 60 * 60 * 24 * 2))
 * // Returns: "February 4, 2026 at 10:30" (formatted date)
 */
export function timeAgo(date: Date | string, numericDates: boolean = true): string {
  const dateObj = typeof date === 'string' ? new Date(date) : date;

  // Check if date is valid
  if (isNaN(dateObj.getTime())) {
    return 'Invalid date';
  }

  const now = new Date();
  const diffMs = now.getTime() - dateObj.getTime();

  // Calculate time units
  const seconds = Math.floor(diffMs / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  // For times older than 1 day, show formatted date with time
  if (days >= 1) {
    return formatDateTime(dateObj, true);
  } else if (hours >= 2) {
    return `${hours} hours ago`;
  } else if (hours >= 1) {
    return numericDates ? '1 hour ago' : 'An hour ago';
  } else if (minutes >= 2) {
    return `${minutes} minutes ago`;
  } else if (minutes >= 1) {
    return numericDates ? '1 minute ago' : 'A minute ago';
  } else if (seconds >= 3) {
    return `${seconds} seconds ago`;
  } else {
    return 'Just now';
  }
}

/**
 * Formats a duration in seconds into a human-readable string.
 * Supports both long-form ("5 minutes 30 seconds") and short-form ("5m 30s") output.
 *
 * @param seconds - The duration in seconds, or start/end timestamps to calculate duration
 * @param endTime - Optional end time in seconds. If provided, duration is calculated as endTime - seconds
 * @param shortForm - Whether to use short form ("5m 30s") instead of long form ("5 minutes 30 seconds")
 * @returns A human-readable duration string
 *
 * @example
 * formatDuration(125)
 * // Returns: "2 minutes 5 seconds"
 *
 * formatDuration(125, undefined, true)
 * // Returns: "2m 5s"
 *
 * formatDuration(1609459200, 1609459325)
 * // Returns: "2 minutes 5 seconds"
 *
 * formatDuration(3661)
 * // Returns: "1 hour 1 minute 1 second"
 */
export function formatDuration(
  seconds: number,
  endTime?: number,
  shortForm: boolean = false
): string {
  // Calculate duration if endTime is provided
  const duration = endTime !== undefined ? endTime - seconds : seconds;

  if (duration < 1) return shortForm ? '<1s' : '<1 second';

  const secs = Math.floor(duration);
  const mins = Math.floor(secs / 60);
  const hours = Math.floor(mins / 60);
  const days = Math.floor(hours / 24);

  if (shortForm) {
    // Short form: "5d 3h", "3h 45m", "45m 30s", "30s"
    if (days > 0) {
      return `${days}d ${hours % 24}h`;
    } else if (hours > 0) {
      return `${hours}h ${mins % 60}m`;
    } else if (mins > 0) {
      return `${mins}m ${secs % 60}s`;
    } else {
      return `${secs}s`;
    }
  } else {
    // Long form: "5 days 3 hours", "3 hours 45 minutes", etc.
    if (days >= 1) {
      const remainingHours = hours % 24;
      if (remainingHours === 0) return days === 1 ? '1 day' : `${days} days`;
      const dayText = days === 1 ? '1 day' : `${days} days`;
      const hourText = remainingHours === 1 ? '1 hour' : `${remainingHours} hours`;
      return `${dayText} ${hourText}`;
    }
    if (hours >= 1) {
      const remainingMins = mins % 60;
      if (remainingMins === 0) return hours === 1 ? '1 hour' : `${hours} hours`;
      const hourText = hours === 1 ? '1 hour' : `${hours} hours`;
      const minText = remainingMins === 1 ? '1 minute' : `${remainingMins} minutes`;
      return `${hourText} ${minText}`;
    }
    if (mins >= 1) {
      const remainingSecs = secs % 60;
      if (remainingSecs === 0) return mins === 1 ? '1 minute' : `${mins} minutes`;
      const minText = mins === 1 ? '1 minute' : `${mins} minutes`;
      const secText = remainingSecs === 1 ? '1 second' : `${remainingSecs} seconds`;
      return `${minText} ${secText}`;
    }
    return secs === 1 ? '1 second' : `${secs} seconds`;
  }
}

/**
 * Word list for generating random paths
 */
const wordList = [
  'acrobat',
  'albino',
  'album',
  'alcohol',
  'alpha',
  'analog',
  'animal',
  'antenna',
  'apollo',
  'april',
  'aroma',
  'artist',
  'aspirin',
  'athlete',
  'atlas',
  'banana',
  'bandit',
  'banjo',
  'bikini',
  'bingo',
  'bonus',
  'camera',
  'anada',
  'carbon',
  'casino',
  'catalog',
  'cinema',
  'citizen',
  'cobra',
  'comet',
  'compact',
  'complex',
  'context',
  'credit',
  'critic',
  'crystal',
  'culture',
  'delta',
  'dialog',
  'diploma',
  'doctor',
  'domino',
  'dragon',
  'drama',
  'extra',
  'fabric',
  'final',
  'focus',
  'forum',
  'galaxy',
  'gallery',
  'global',
  'harmony',
  'hotel',
  'humor',
  'index',
  'kilo',
  'lemon',
  'liter',
  'lotus',
  'mango',
  'melon',
  'menu',
  'meter',
  'metro',
  'mineral',
  'model',
  'music',
  'object',
  'piano',
  'pirate',
  'plastic',
  'radio',
  'report',
  'signal',
  'sport',
  'studio',
  'subject',
  'super',
  'tango',
  'taxi',
  'tempo',
  'tennis',
  'textile',
  'total',
  'tourist',
  'video',
  'visa',
  'academy',
  'atomic',
  'bazaar',
  'brother',
  'budget',
  'cabaret',
  'cadet',
  'candle',
  'capsule',
  'caviar',
  'channel',
  'chapter',
  'circle',
  'cobalt',
  'comrade',
  'condor',
  'crimson',
  'cyclone',
  'declare',
  'desert',
  'divide',
  'domain',
  'double',
  'eagle',
  'echo',
  'eclipse',
  'editor',
  'educate',
  'effect',
  'electra',
  'emerald',
  'emotion',
  'empire',
  'eternal',
  'evening',
  'exhibit',
  'expand',
  'explore',
  'extreme',
  'forget',
  'freedom',
  'gravity',
  'habitat',
  'helium',
  'holiday',
  'hunter',
  'iceberg',
  'imagine',
  'infant',
  'isotope',
  'kitchen',
  'letter',
  'license',
  'lithium',
  'loyal',
  'lucky',
  'magenta',
  'manual',
  'marble',
  'mayor',
  'monarch',
  'money',
  'morning',
  'mother',
  'mystery',
  'native',
  'nectar',
  'network',
  'nobody',
  'nominal',
  'nothing',
  'number',
  'office',
  'opinion',
  'option',
  'order',
  'outside',
  'package',
  'pattern',
  'pencil',
  'people',
  'phantom',
  'pioneer',
  'podium',
  'portal',
  'potato',
  'process',
  'proxy',
  'pupil',
  'python',
  'quality',
  'quarter',
  'quiet',
  'rabbit',
  'radical',
  'radius',
  'rainbow',
  'ravioli',
  'respect',
  'respond',
  'result',
  'resume',
  'river',
  'salary',
  'salsa',
  'sample',
  'savage',
  'scarlet',
  'sector',
  'serpent',
  'shampoo',
  'silence',
  'simple',
  'society',
  'sonar',
  'sonata',
  'soprano',
  'spider',
  'sponsor',
  'action',
  'active',
  'actor',
  'address',
  'admiral',
  'agenda',
  'agent',
  'airline',
  'airport',
  'alarm',
  'algebra',
  'alibi',
  'alien',
  'almond',
  'alpine',
  'ammonia',
  'analyze',
  'anatomy',
  'angel',
  'annual',
  'answer',
  'apple',
  'archive',
  'arctic',
  'arena',
  'armada',
  'aspect',
  'audio',
  'august',
  'avenue',
  'average',
  'axiom',
  'bagel',
  'balance',
  'ballad',
  'ballet',
  'bambino',
  'bamboo',
  'baron',
  'basic',
  'basket',
  'battery',
  'benefit',
  'bicycle',
  'binary',
  'biology',
  'bishop',
  'blitz',
  'block',
  'blonde',
  'bonjour',
  'bottle',
  'boxer',
  'brandy',
  'bravo',
  'bridge',
  'bronze',
  'brown',
  'burger',
  'cabinet',
  'cactus',
  'cafe',
  'camel',
  'campus',
  'canal',
  'cannon',
  'canoe',
  'cantina',
  'canvas',
  'canyon',
  'capital',
  'caramel',
  'caravan',
  'career',
  'cargo',
  'carpet',
  'cartel',
  'cartoon',
  'castle',
  'cement',
  'center',
  'century',
  'ceramic',
  'chamber',
  'chance',
  'change',
  'chaos',
  'charm',
  'charter',
  'cheese',
  'chef',
  'chemist',
  'cherry',
  'chess',
  'chicken',
  'chief',
  'cigar',
  'circus',
  'city',
  'classic',
  'clean',
  'client',
  'climax',
  'clinic',
  'clock',
  'club',
  'cockpit',
  'coconut',
  'cola',
  'collect',
  'colony',
  'combat',
  'comedy',
  'command',
  'company',
  'concert',
  'connect',
  'consul',
  'contact',
  'contour',
  'control',
  'convert',
  'copy',
  'corner',
  'corona',
  'correct',
  'cosmos',
  'couple',
  'courage',
  'cowboy',
  'craft',
  'crash',
  'cricket',
  'crown',
  'dance',
  'decade',
  'decimal',
  'degree',
  'delete',
  'deliver',
  'deluxe',
  'demand',
  'demo',
  'design',
  'detect',
  'develop',
  'diagram',
  'diamond',
  'diesel',
  'diet',
  'digital',
  'dilemma',
  'direct',
  'disco',
  'distant',
  'dollar',
  'dolphin',
  'drink',
  'driver',
  'duet',
  'dynamic',
  'earth',
  'east',
  'ecology',
  'economy',
  'elastic',
  'elegant',
  'element',
  'elite',
  'email',
  'empty',
  'energy',
  'engine',
  'english',
  'episode',
  'equator',
  'escape',
  'escort',
  'ethnic',
  'evident',
  'exact',
  'example',
  'exit',
  'exotic',
  'export',
  'express',
  'factor',
  'falcon',
  'family',
  'fantasy',
  'fashion',
  'fiber',
  'fiction',
  'fiesta',
  'figure',
  'film',
  'filter',
  'finance',
  'finish',
  'first',
  'flag',
  'flash',
  'flower',
  'fluid',
  'flute',
  'folio',
  'forest',
  'formal',
  'formula',
  'fortune',
  'forward',
  'fragile',
  'fresh',
  'friend',
  'frozen',
  'future',
  'gamma',
  'garage',
  'garden',
  'garlic',
  'gemini',
  'general',
  'genetic',
  'genius',
  'gold',
  'golf',
  'gondola',
  'gong',
  'good',
  'gorilla',
  'grand',
  'granite',
  'graph',
  'green',
  'group',
  'guide',
  'guitar',
  'guru',
  'hand',
  'happy',
  'harbor',
  'hello',
  'history',
  'horizon',
  'house',
  'human',
  'icon',
  'idea',
  'igloo',
  'image',
  'impact',
  'import',
  'input',
  'insect',
  'instant',
  'iris',
  'jacket',
  'jaguar',
  'jargon',
  'jazz',
  'jeep',
  'joker',
  'journey',
  'juice',
  'jungle',
  'kale',
  'karma',
  'keen',
  'kettle',
  'kiwi',
  'knife',
  'knot',
  'lab',
  'lady',
  'laser',
  'launch',
  'leader',
  'legend',
  'legal',
  'leisure',
  'lesson',
  'level',
  'liberty',
  'linear',
  'local',
  'logic',
  'lotto',
  'lounge',
  'loyalty',
  'lyrics',
  'mail',
  'major',
  'mall',
  'manager',
  'map',
  'market',
  'mask',
  'metal',
  'meter',
  'midnight',
  'miracle',
  'mirror',
  'mission',
  'modem',
  'monitor',
  'moral',
  'naval',
  'navigare',
  'needle',
  'neon',
  'neutral',
  'newton',
  'normal',
  'oasis',
  'ocean',
  'office',
  'old',
  'opera',
  'organic',
  'oxygen',
  'painter',
  'palace',
  'palma',
  'parade',
  'paris',
  'pastel',
  'pearl',
  'pedal',
  'pelican',
  'pepper',
  'phoenix',
  'pillar',
  'pink',
  'planet',
  'plastic',
  'platform',
  'player',
  'plus',
  'poem',
  'polar',
  'pope',
  'port',
  'pot',
  'power',
  'prism',
  'prince',
  'printer',
  'prize',
  'program',
  'public',
  'quest',
  'quota',
  'race',
  'rail',
  'raisin',
  'rally',
  'random',
  'rapid',
  'ratio',
  'reactor',
  'reader',
  'relief',
  'rhythm',
  'rigid',
  'river',
  'rocket',
  'rose',
  'route',
  'royal',
  'safari',
  'sample',
  'sapphire',
  'scheme',
  'school',
  'science',
  'scout',
  'second',
  'secret',
  'segment',
  'series',
  'shadow',
  'share',
  'shelter',
  'shift',
  'signal',
  'silver',
  'simple',
  'singer',
  'sister',
  'skate',
  'sky',
  'smart',
  'smoke',
  'soap',
  'soda',
  'soft',
  'solar',
  'solid',
  'sonic',
  'soul',
  'source',
  'south',
  'sovereign',
  'spare',
  'spark',
  'speed',
  'spider',
  'spirit',
  'sponge',
  'square',
  'star',
  'station',
  'steel',
  'stone',
  'storm',
  'strong',
  'studio',
  'style',
  'sugar',
  'summit',
  'summer',
  'sunday',
  'sunset',
  'superior',
  'support',
  'survey',
  'symbol',
  'table',
  'target',
  'team',
  'tempo',
  'tennis',
  'text',
  'think',
  'tiger',
  'tilt',
  'timber',
  'titan',
  'tonic',
  'total',
  'tower',
  'toy',
  'track',
  'trade',
  'traffic',
  'train',
  'trick',
  'trip',
  'trooper',
  'trust',
  'turbo',
  'turn',
  'ultra',
  'union',
  'unique',
  'unity',
  'urban',
  'vanilla',
  'vegan',
  'vehicle',
  'version',
  'vessel',
  'video',
  'vision',
  'vital',
  'vivid',
  'voice',
  'volcano',
  'voltage',
  'volume',
  'voyage',
  'wagon',
  'walk',
  'wall',
  'warrior',
  'waste',
  'watch',
  'water',
  'weather',
  'wedding',
  'week',
  'weight',
  'west',
  'wheel',
  'whiskey',
  'white',
  'window',
  'wisdom',
  'wish',
  'world',
  'writer',
  'xylophone',
  'yellow',
  'zebra',
  'zero',
  'zodiac',
  'zoo',
];

/**
 * Gets a random word from the word list
 *
 * @returns A random word from the word list
 *
 * @example
 * getRandomWord()
 * // Returns: "dragon" (or any other word from the list)
 */
export function getRandomWord(): string {
  return wordList[Math.floor(Math.random() * wordList.length)];
}

/**
 * Generates a random path in the format /word1/word2
 *
 * @returns A random path with two words separated by slashes
 *
 * @example
 * generateRandomPath()
 * // Returns: "/dragon/castle" (or any other combination)
 */
export function generateRandomPath(): string {
  return `/${getRandomWord()}/${getRandomWord()}`;
}

/**
 * Converts a string to a valid secret ID in snake_case format.
 * Only allows A-Z, a-z, 0-9, underscore (_), and hyphen (-).
 * Removes or replaces all other characters.
 *
 * @param name - The secret name to convert
 * @returns A snake_case identifier safe for use in $SECRET:xxx syntax
 *
 * @example
 * toSecretId("My API Key")
 * // Returns: "my_api_key"
 *
 * toSecretId("Production-Database@2024")
 * // Returns: "production_database_2024"
 *
 * toSecretId("AWS_S3_Access_Token")
 * // Returns: "aws_s3_access_token"
 */
export function toSecretId(name: string): string {
  return (
    name
      .toLowerCase()
      .trim()
      // Replace whitespace and common separators with underscore
      .replace(/[\s.-]+/g, '_')
      // Remove any characters that aren't alphanumeric, underscore, or hyphen
      .replace(/[^a-z0-9_-]/g, '')
      // Replace multiple consecutive underscores with single underscore
      .replace(/_+/g, '_')
      // Remove leading/trailing underscores or hyphens
      .replace(/^[_-]+|[_-]+$/g, '')
  );
}

/**
 * Format a log timestamp according to user preference
 * @param timestamp - Unix timestamp (seconds)
 * @param format - Display format preference
 * @returns Formatted timestamp string
 */
export function formatLogTimestamp(
  timestamp: number,
  format: 'utc' | 'local' | 'relative' | 'compact' = 'local'
): string {
  // timestamp is in milliseconds (Unix epoch)
  const date = new Date(timestamp);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSecs = Math.floor(diffMs / 1000);

  switch (format) {
    case 'utc':
      // ISO 8601 UTC format: 2025-01-07T10:30:45.123Z
      return date.toISOString();

    case 'local':
      // Local datetime: 01/07/2025, 10:30:45.123
      return date.toLocaleString(undefined, {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        fractionalSecondDigits: 3,
        hour12: false,
      } as Intl.DateTimeFormatOptions);

    case 'relative':
      // Relative time: "2 minutes ago", "just now"
      if (diffSecs < 10) return 'just now';
      if (diffSecs < 60) return `${diffSecs}s ago`;
      if (diffSecs < 3600) return `${Math.floor(diffSecs / 60)}m ago`;
      if (diffSecs < 86400) return `${Math.floor(diffSecs / 3600)}h ago`;
      return `${Math.floor(diffSecs / 86400)}d ago`;

    case 'compact':
      // Compact time only: 10:30:45.123
      return date.toLocaleTimeString(undefined, {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        fractionalSecondDigits: 3,
        hour12: false,
      } as Intl.DateTimeFormatOptions);

    default:
      return date.toLocaleString();
  }
}

/**
 * Formats a DID (Decentralized Identifier) for compact display by intelligently
 * shortening different DID types while preserving important information.
 *
 * Handles various DID formats:
 * - did:web:HOST:channel:UUID → did::channel:12345678...12345678
 * - did:key:MULTIBASE_KEY → did:key:z6Mk...abcd
 * - did:peer:HASH → did:peer:2.V...abcd
 * - Generic DIDs → did:METHOD:12345678...12345678
 *
 * @param did - The DID string to format
 * @param firstChars - Number of characters to show at start of identifier (default: 8)
 * @param lastChars - Number of characters to show at end of identifier (default: 8)
 * @returns Formatted DID string for display
 *
 * @example
 * formatDID("did:web:agent-gateway-1.example.com:channel:1524042a-2339-4e08-af51-2c5fd43f7b7e")
 * // Returns: "did::channel:1524042a...2c5fd43f7b7e"
 *
 * formatDID("did:key:z6ExampleKeyId000001")
 * // Returns: "did:key:z6Exampl...Id000001"
 *
 * formatDID("did:peer:2.VzExamplePeerId0001")
 * // Returns: "did:peer:2.VzExam...erId0001"
 */
export function formatDID(did: string, firstChars: number = 8, lastChars: number = 8): string {
  if (!did || !did.startsWith('did:')) {
    return did; // Not a valid DID, return as-is
  }

  const parts = did.split(':');

  if (parts.length < 3) {
    return did; // Invalid DID format, return as-is
  }

  const method = parts[1]; // e.g., "web", "key", "peer"

  // Handle did:web specifically - format: did:web:HOST:channel:UUID
  if (method === 'web' && parts.length >= 5) {
    // Check if it's the channel format with UUID at the end
    const lastPart = parts[parts.length - 1];
    const secondLastPart = parts[parts.length - 2];

    // If second-to-last is "channel" and last part looks like a UUID, format it
    if (secondLastPart === 'channel' && lastPart.length >= firstChars + lastChars) {
      const shortUuid = `${lastPart.substring(0, firstChars)}...${lastPart.substring(lastPart.length - lastChars)}`;
      return `did::channel:${shortUuid}`;
    }
  }

  // For all other DID types (did:key, did:peer, etc.), shorten the identifier part
  // The identifier is everything after "did:method:"
  const identifier = parts.slice(2).join(':');

  if (identifier.length <= firstChars + lastChars + 3) {
    return did; // Too short to truncate meaningfully
  }

  const shortIdentifier = `${identifier.substring(0, firstChars)}...${identifier.substring(identifier.length - lastChars)}`;
  return `did:${method}:${shortIdentifier}`;
}
