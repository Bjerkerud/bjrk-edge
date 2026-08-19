
// stub module to test header files' C++ compatibility

extern "C" {
  #include <bjrk-edge_config.h>
  #include <bjrk-edge_core.h>
  #include <bjrk-edge_event.h>
  #include <bjrk-edge_event_connect.h>
  #include <bjrk-edge_event_pipe.h>

  #include <bjrk-edge_http.h>

  #include <bjrk-edge_mail.h>
  #include <bjrk-edge_mail_pop3_module.h>
  #include <bjrk-edge_mail_imap_module.h>
  #include <bjrk-edge_mail_smtp_module.h>

  #include <bjrk-edge_stream.h>
}

// nginx header files should go before other, because they define 64-bit off_t
// #include <string>


void ngx_cpp_test_handler(void *data);

void
ngx_cpp_test_handler(void *data)
{
    return;
}
