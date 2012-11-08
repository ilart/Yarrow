#ifndef HMAC_WHIRLPOOL_H_
#define HMAC_WHIRLPOOL_H_

void hmac_whirlpool(const void *key, unsigned nkey, const void *msg,
		    unsigned nmsg, unsigned char hmac[64]);

void *
pbkdf2_hmac_whirlpool(const void	*pass,
		      unsigned		npass,
		      const void	*salt,
		      unsigned		nsalt,
		      int		niter,
		      void		*key,
		      unsigned		nkey);

#endif

