import os

def cleanup( settings ):
    if os.path.exists( settings.cache().filepath ):
        os.remove( settings.cache().filepath )

    if os.path.exists( settings.bookmark().filepath ):
        os.remove( settings.bookmark().filepath )
