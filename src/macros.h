// macros.h
// ISA, 30.09.2018
// Author: Daniel Dolejska, FIT

#ifndef _MACROS_H
#define _MACROS_H

#define DEBUG_PRINT_ENABLED

#ifdef DEBUG_PRINT_ENABLED
#define DEBUG_PRINT(...) do{ fprintf( stderr, __VA_ARGS__ ); } while( 0 )
#else
#define DEBUG_PRINT(...) do{ } while ( 0 )
#endif // DEBUG_PRINT_ENABLED

#ifdef DEBUG_LOG_ENABLED
#define DEBUG_LOG(...) do{ fprintf( stderr, "[%s]     %s\n", __VA_ARGS__ ); } while( 0 )
#else
#define DEBUG_LOG(...) do{ } while ( 0 )
#endif // DEBUG_LOG_ENABLED

#ifdef DEBUG_ERR_ENABLED
#define DEBUG_ERR(...) do{ fprintf( stderr, "[%s] ERR %s\n", __VA_ARGS__ ); } while( 0 )
#else
#define DEBUG_ERR(...) do{ } while ( 0 )
#endif // DEBUG_ERR_ENABLED

#define ERR(...) do{ fprintf( stderr, __VA_ARGS__ ); } while( 0 )
#define OUTPUT(...) do{ fprintf( stdout, __VA_ARGS__ ); } while( 0 )

#define UINT8_STRLEN    (3 * sizeof(uint8_t)  + 2)
#define UINT16_STRLEN   (3 * sizeof(uint16_t) + 2)
#define UINT32_STRLEN   (3 * sizeof(uint32_t) + 2)

#endif //_MACROS_H
