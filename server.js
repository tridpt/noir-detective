/**
 * 🕵️‍♂️ NoirDetective — Trung Tâm Điều Tra Hiện Trường, Pháp Y Số & Thẩm Vấn Phá Án Tương Tác (Port 4130)
 * - Khám nghiệm hiện trường tương tác (Crime Scene & Digital Forensics Lab)
 * - Thẩm vấn nghi phạm kèm Máy đo nói dối thời gian thực (Polygraph BPM / GSR / Voice Stress)
 * - Bẻ gãy bằng chứng ngoại phạm (Alibi Breaker Matrix: Đối chiếu Lời khai vs Bằng chứng vật lý/số)
 * - Sinh vụ án ngẫu nhiên có suy luận logic chặt chẽ (Procedural Mystery Generator)
 * - Cầu nối liên thông đẩy dấu vết số (Burner Phone, IP, Email, Crypto) sang OmniTrace OSINT (Port 4090)
 */

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { URL } = require('node:url');

const PORT = Number(process.env.PORT || 4130);
const PUBLIC_DIR = path.join(__dirname, 'public');

// ============================================================================
// 1. KHO KỊCH BẢN VỤ ÁN ĐIỂN HÌNH + BỘ SINH VỤ ÁN NGẪU NHIÊN (PROCEDURAL)
// ============================================================================

function createPresetCases() {
  return [
    {
      id: 'case-chimera-lab',
      code: 'NOIR-2026-089',
      title: 'Bóng Ma Phòng Lab AI "Project Chimera"',
      location: 'Tầng hầm B3 — Trung tâm Nghiên cứu Lượng tử & AI Aegis (Quận Hoàn Kiếm)',
      timeOfIncident: '23:15 Đêm Mưa Bão',
      victim: {
        name: 'TS. Trần Minh Triết (46 tuổi)',
        role: 'Kiến trúc sư trưởng mô hình tự nhận thức Chimera-9',
        causeOfDeath: 'Ngộ độc khí thần kinh tổng hợp phát tán qua hệ thống tản nhiệt chất lỏng máy chủ, kèm mất cắp ổ cứng lượng tử chứa trọng số gốc.'
      },
      summary:
        'Đúng 23:15 khi tòa nhà chuyển sang nguồn điện dự phòng do sét đánh, TS. Triết gục xuống bên cạnh cụm máy chủ H100. Cửa từ sinh trắc học không có dấu hiệu cạy phá từ bên ngoài. Ổ cứng chứa trọng số mô hình trị giá 40 triệu USD đã biến mất.',
      culpritId: 'suspect-linh',
      correctMotive: 'Đánh cắp trọng số Chimera-9 để bán cho tổ chức môi giới dữ liệu ngầm trên Darknet trước khi bị kiểm toán bảo mật phát hiện.',
      decisiveEvidenceId: 'ev-badge-spoof',
      iocs: [
        '185.220.101.77',
        'chimera-drop-vault.top',
        '0918445902',
        'linh.phantom.key@proton.me'
      ],
      suspects: [
        {
          id: 'suspect-linh',
          name: 'Đặng Bảo Linh (29 tuổi)',
          role: 'Kỹ sư Bảo mật Hạ tầng & Mạng Nội bộ',
          avatar: '👩‍💻',
          initialAlibi:
            'Từ 22:45 đến 23:30 tôi ở phòng SOC tầng 5 để trực xử lý sự cố sụt áp điện lưới, hoàn toàn không xuống tầng hầm B3.',
          trueSecret:
            'Đã dùng thiết bị Flipper/Proxmark nhân bản thẻ từ của Phó Giám đốc Khải lúc 23:08 để mở cửa B3 và cài script tự động xóa log camera.',
          baseBpm: 78,
          stressLevel: 38,
          alibiBroken: false,
          contradictingEvidenceId: 'ev-badge-spoof',
          interrogationResponses: {
            PRESS_ALIBI:
              'Tôi đã nói rồi! Hệ thống chấm công tầng 5 ghi nhận tài khoản của tôi vẫn gõ lệnh ping liên tục lúc 23:15!',
            GOOD_COP:
              'TS. Triết rất khắt khe nhưng tôi luôn tôn trọng ông ấy. Chỉ là... gần đây ông ấy nghi ngờ có người rò rỉ kiến trúc mô hình ra ngoài.',
            POLYGRAPH_TRAP:
              'Tại sao kim máy đo lại giật?! Chỉ vì phòng thẩm vấn này ngột ngạt thôi, tôi không hề chạm vào hệ thống tản nhiệt!',
            BROKEN:
              '💥 [NGOẠI PHẠM SỤP ĐỔ] Được rồi... Những lệnh ping ở tầng 5 là do cronjob tự động tôi hẹn giờ sẵn! Chính tôi đã mang thẻ từ nhân bản xuống tầng B3 lúc 23:11 để rút ổ cứng Chimera-9!'
          }
        },
        {
          id: 'suspect-khai',
          name: 'Lê Hoàng Khải (41 tuổi)',
          role: 'Phó Giám đốc Thương mại hóa AI',
          avatar: '🕴️',
          initialAlibi:
            'Tôi rời tòa nhà lúc 22:30 và ngồi uống rượu vang tại quán Noir Lounge cách đó 3km, nhưng thẻ từ của tôi lại để quên trên bàn làm việc.',
          trueSecret:
            'Đang nợ nần cờ bạc nhưng thực sự ở quán Noir Lounge; việc thẻ của ông ta quẹt ở tầng B3 là do bị Bảo Linh nhân bản RFID.',
          baseBpm: 84,
          stressLevel: 45,
          alibiBroken: false,
          contradictingEvidenceId: 'ev-lounge-receipt',
          interrogationResponses: {
            PRESS_ALIBI:
              'Tôi thừa nhận có tranh cãi gay gắt với TS. Triết chiều hôm đó vì ông ấy từ chối bán bản quyền Chimera, nhưng 23:15 tôi đang ở quán bar!',
            GOOD_COP:
              'Thẻ từ VIP của tôi để trong ngăn kéo không khóa từ 19:00 tối. Bất kỳ ai có quyền vào khu văn phòng tầng 4 đều có thể tiếp cận nó.',
            POLYGRAPH_TRAP:
              'Tim tôi đập nhanh vì sợ bị đổ tội oan! Các anh cứ kiểm tra camera giao thông và hóa đơn thanh toán ở Noir Lounge đi!',
            BROKEN:
              '🔍 [LÀM RÕ NGOẠI PHẠM] Đúng là hóa đơn chứng minh tôi ở Noir Lounge lúc 23:12! Ai đó trong phòng bảo mật đã nhân bản mã RFID thẻ của tôi!'
          }
        },
        {
          id: 'suspect-minh',
          name: 'Vũ Quang Minh (34 tuổi)',
          role: 'Trợ lý Nghiên cứu Cấp cao của Nạn nhân',
          avatar: '🧪',
          initialAlibi:
            'Tôi ở phòng thí nghiệm hóa sinh tầng 2 để chạy mô phỏng làm mát chất lỏng cho đến khi chuông báo động toàn tòa nhà vang lên lúc 23:25.',
          trueSecret:
            'Từng bị TS. Triết từ chối đứng tên đồng tác giả bài báo, và đã vô tình để lộ công thức dung dịch làm mát cho Bảo Linh 3 ngày trước.',
          baseBpm: 74,
          stressLevel: 32,
          alibiBroken: false,
          contradictingEvidenceId: 'ev-coolant-vial',
          interrogationResponses: {
            PRESS_ALIBI:
              'Camera hành lang tầng 2 vẫn hoạt động bằng pin UPS mà! Tôi không hề bước chân vào thang máy xuống B3!',
            GOOD_COP:
              'Thực ra... 3 ngày trước Bảo Linh có hỏi tôi rất kỹ về nhiệt độ bay hơi của chất phụ gia trong hệ thống tản nhiệt máy chủ.',
            POLYGRAPH_TRAP:
              'Tôi có bất mãn chuyện bài báo khoa học, nhưng tôi là nhà khoa học chứ không phải kẻ giết người!',
            BROKEN:
              '⚠️ [MẤU CHỐT HÓA CHẤT] Tôi thừa nhận lọ chất xúc tác bị mất trong tủ khóa tầng 2 là của tôi, nhưng log mở tủ bằng vân tay giả trùng khớp với thiết bị điều khiển từ xa từ phòng SOC!'
          }
        }
      ],
      evidence: [
        {
          id: 'ev-badge-spoof',
          name: 'Nhật ký Cổng từ B3 & Dấu sóng RFID Bất thường',
          category: 'DIGITAL_FORENSICS',
          icon: '💳',
          locationFound: 'Bộ điều khiển cửa từ Sinh trắc học Tầng B3',
          initialSummary:
            'Log ghi nhận thẻ VIP của Phó GĐ Lê Hoàng Khải mở cửa B3 lúc 23:11, nhưng độ trễ phản hồi tín hiệu khác thường.',
          deepForensicResult:
            '🔬 [PHÁP Y SỐ]: Phân tích xung điện từ cho thấy thẻ quẹt lúc 23:11 phát từ bộ giả lập tần số kép (Proxmark3/Flipper) gắn MAC nội bộ của máy trạm SOC-01 (do Đặng Bảo Linh quản lý). Đồng thời phát hiện cronjob giả lập gõ phím tại máy của Linh từ 22:50–23:30!',
          inspected: false,
          linkedSuspectId: 'suspect-linh',
          iocExtracted: '185.220.101.77'
        },
        {
          id: 'ev-server-usb',
          name: 'Dấu vết Rút Ổ cứng NVMe & Kết nối C2 Ngầm',
          category: 'CYBER_TRACE',
          icon: '💾',
          locationFound: 'Cụm máy chủ AI H100 — Rack #04',
          initialSummary:
            'Khe cắm NVMe chứa trọng số Chimera-9 bị tháo nóng lúc 23:14. Tường lửa ghi nhận một gói tin đồng bộ khóa giải mã ra ngoài.',
          deepForensicResult:
            '🔬 [PHÁP Y MẠNG]: Gói tin TLS gửi khóa giải mã tới domain `chimera-drop-vault.top` (IP `185.220.101.77`) được ký bằng SSH Key cá nhân `linh.phantom.key@proton.me`.',
          inspected: false,
          linkedSuspectId: 'suspect-linh',
          iocExtracted: 'chimera-drop-vault.top'
        },
        {
          id: 'ev-coolant-vial',
          name: 'Ống Thủy Tinh Chứa Dư Lượng Khí Thần Kinh',
          category: 'CHEMICAL_LAB',
          icon: '🧪',
          locationFound: 'Van nạp chất lỏng tản nhiệt Máy chủ B3',
          initialSummary:
            'Một ống thủy tinh nhỏ gắn van hẹn giờ nhiệt độ được lắp vào đường ống tản nhiệt, phát tán độc tố khi GPU đạt 80°C.',
          deepForensicResult:
            '🔬 [PHÁP Y HÓA SINH]: Vỏ ống không có vân tay thật nhưng dính sợi vải găng tay chống tĩnh điện loại chỉ cấp riêng cho kỹ sư phòng SOC tầng 5.',
          inspected: false,
          linkedSuspectId: 'suspect-minh',
          iocExtracted: '0918445902'
        },
        {
          id: 'ev-lounge-receipt',
          name: 'Hóa Đơn POS & Camera Giao Thông Quán Noir Lounge',
          category: 'TIMELINE_CHECK',
          icon: '🧾',
          locationFound: 'Quán Noir Lounge (Cách hiện trường 3.2 km)',
          initialSummary:
            'Hóa đơn thanh toán thẻ tín dụng mang tên Lê Hoàng Khải lúc 23:12.',
          deepForensicResult:
            '🔬 [XÁC MINH THỜI GIAN]: Camera quầy bar xác nhận ông Khải có mặt trực tiếp lúc 23:12, chứng minh thẻ từ của ông ta tại tầng B3 lúc 23:11 chắc chắn là bản sao chép (Cloned RFID).',
          inspected: false,
          linkedSuspectId: 'suspect-khai',
          iocExtracted: 'linh.phantom.key@proton.me'
        }
      ],
      timeline: [
        { time: '22:30', event: 'Phó GĐ Khải rời tòa nhà đến Noir Lounge, bỏ quên thẻ từ VIP tại bàn.' },
        { time: '22:50', event: 'Bảo Linh kích hoạt script tự động gõ lệnh ping giả tạo bằng chứng ngoại phạm tại phòng SOC tầng 5.' },
        { time: '23:11', event: 'Cửa tầng hầm B3 mở bằng tín hiệu RFID nhân bản từ thiết bị Proxmark3.' },
        { time: '23:14', event: 'Ổ cứng chứa trọng số Chimera-9 bị tháo nóng; van nhiệt tản nhiệt phát tán độc tố.' },
        { time: '23:15', event: 'Khóa giải mã được đẩy ngầm tới máy chủ C2 185.220.101.77.' }
      ]
    },
    {
      id: 'case-cold-wallet-express',
      code: 'NOIR-2026-104',
      title: 'Chuyến Tàu Đêm Đông Dương & Chiếc Ví Lạnh 500 BTC',
      location: 'Toa VIP #01 — Tàu Tốc Hành Đêm Hà Nội ➔ Đà Nẵng',
      timeOfIncident: '01:40 Rạng Sáng (Khi tàu qua hầm Hải Vân)',
      victim: {
        name: 'Triệu phú Tiền số Marcus Vũ (38 tuổi)',
        role: 'Nhà sáng lập Quỹ đầu tư Lotus DeFi',
        causeOfDeath: 'Bị tiêm thuốc mê liều cao dẫn đến ngừng tim trong khoang khóa kín; chiếc ví lạnh Ledger Titanium chứa 500 BTC biến mất.'
      },
      summary:
        'Trong 9 phút tàu đi vào hầm tối đèo Hải Vân và mất sóng di động, Marcus Vũ bị sát hại trong khoang riêng. Chỉ có 3 người có mặt trên toa VIP #01.',
      culpritId: 'suspect-bach',
      correctMotive: 'Chiếm đoạt chiếc ví lạnh 500 BTC để bù vào khoản lỗ thanh khoản quỹ khách hàng trước giờ kiểm toán sáng hôm sau.',
      decisiveEvidenceId: 'ev-bluetooth-sniffer',
      iocs: [
        '103.148.204.91',
        'lotus-bridge-mixer.xyz',
        '0987112309',
        'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh'
      ],
      suspects: [
        {
          id: 'suspect-bach',
          name: 'Trịnh Gia Bạch (35 tuổi)',
          role: 'Giám đốc Tài chính (CFO) Quỹ Lotus DeFi',
          avatar: '💼',
          initialAlibi:
            'Tôi nằm ngủ trong khoang #03 suốt từ 01:00 đến 02:30, điện thoại để chế độ máy bay và không bước ra hành lang.',
          trueSecret:
            'Đã dùng đồng hồ thông minh kết nối Bluetooth với ví lạnh Ledger Nano X vừa lấy cắp lúc 01:43 ngay trong khoang #03 để ký giao dịch rút 500 BTC.',
          baseBpm: 80,
          stressLevel: 40,
          alibiBroken: false,
          contradictingEvidenceId: 'ev-bluetooth-sniffer',
          interrogationResponses: {
            PRESS_ALIBI:
              'Hành lang toa VIP tối om khi vào hầm, nhưng tôi thề tôi chỉ nằm trong khoang #03 nghe nhạc chống ồn!',
            GOOD_COP:
              'Marcus giữ toàn bộ khóa cá nhân một mình. Tôi chỉ lo phần sổ sách, không biết cụm từ khôi phục (Seed Phrase) của anh ấy.',
            POLYGRAPH_TRAP:
              'Mồ hôi tay tôi ra nhiều là do máy lạnh trên tàu bị hỏng thôi!',
            BROKEN:
              '💥 [NGOẠI PHẠM SỤP ĐỔ] Không thể nào! Sao các anh bắt được gói tin quảng bá BLE của chiếc ví lạnh phát ra từ trong khoang #03 của tôi lúc 01:43?! Đúng, tôi đã lấy nó khi tàu vừa vào hầm!'
          }
        },
        {
          id: 'suspect-lena',
          name: 'Lê Na (27 tuổi)',
          role: 'Y tá Riêng & Chăm sóc Sức khỏe của Nạn nhân',
          avatar: '👩‍⚕️',
          initialAlibi:
            'Tôi pha trà thảo mộc cho ông Marcus lúc 01:10 rồi về khoang #02 nghỉ ngơi.',
          trueSecret:
            'Bị mất chìa khóa túi y tế cá nhân từ lúc 22:00 tối hôm trước khi ngồi ăn tối cùng Gia Bạch ở toa nhà hàng.',
          baseBpm: 76,
          stressLevel: 35,
          alibiBroken: false,
          contradictingEvidenceId: 'ev-syringe-case',
          interrogationResponses: {
            PRESS_ALIBI:
              'Tôi là y tá riêng được trả lương rất hậu hĩnh, nếu ông Marcus mất đi thì tôi mất việc, tôi hại ông ấy làm gì?',
            GOOD_COP:
              'Lúc ăn tối ở toa nhà hàng lúc 21:45, ông Gia Bạch có ngồi cạnh túi y tế của tôi khoảng 10 phút khi tôi đi rửa tay.',
            POLYGRAPH_TRAP:
              'Chai thuốc an thần bị thiếu trong túi y tế thực sự làm tôi hoảng sợ, nhưng tôi không phải người lấy nó!',
            BROKEN:
              '🔍 [LÀM RÕ] Kết quả ADN trên nắp lọ thuốc cho thấy có dấu vết da tay từ chiếc nhẫn kim loại mà chỉ CFO Gia Bạch đeo ở ngón cái!'
          }
        },
        {
          id: 'suspect-tung',
          name: 'Đoàn Thanh Tùng (44 tuổi)',
          role: 'Trưởng Toa VIP Tàu Tốc Hành',
          avatar: '👮',
          initialAlibi:
            'Tôi đứng trực ở đầu toa giáp ranh giữa toa VIP #01 và toa #02 để kiểm soát an ninh khi tàu qua hầm.',
          trueSecret:
            'Đã nhận 500 USD tiền tip của Gia Bạch để tắt bớt đèn hành lang toa VIP từ 01:30 với lý do "cho khách VIP dễ ngủ".',
          baseBpm: 72,
          stressLevel: 30,
          alibiBroken: false,
          contradictingEvidenceId: 'ev-corridor-switch',
          interrogationResponses: {
            PRESS_ALIBI:
              'Tôi đứng ngay cửa nối hai toa, không có bất kỳ ai từ toa khác lọt sang toa VIP #01 cả!',
            GOOD_COP:
              'Thú thật là lúc 01:25 ông Bạch có đưa tôi 5 tờ 100 đô bảo tắt đèn hành lang đi vì ánh sáng lọt qua khe cửa làm ông ấy khó ngủ.',
            POLYGRAPH_TRAP:
              'Tôi chỉ nhận tiền tip để tắt đèn hành lang chứ đâu biết ông ta định lẻn sang phòng ông Marcus!',
            BROKEN:
              '⚠️ [LỜI KHAI QUAN TRỌNG] Chính Trịnh Gia Bạch là người yêu cầu tắt đèn hành lang đúng 10 phút trước khi tàu đi vào hầm Hải Vân!'
          }
        }
      ],
      evidence: [
        {
          id: 'ev-bluetooth-sniffer',
          name: 'Nhật ký Sóng Bluetooth Low Energy (BLE) & Giao dịch Ví Lạnh',
          category: 'DIGITAL_FORENSICS',
          icon: '📡',
          locationFound: 'Bộ thu phát IoT thông minh trên trần Toa VIP #01',
          initialSummary:
            'Hệ thống cảm biến toa tàu ghi nhận tín hiệu ghép nối Bluetooth của thiết bị Ledger Nano X lúc 01:43.',
          deepForensicResult:
            '🔬 [PHÁP Y SỐ]: Cường độ tín hiệu RSSI (-38 dBm) định vị chính xác chiếc ví lạnh Ledger của nạn nhân được bật và ghép nối với điện thoại của Trịnh Gia Bạch ngay bên trong Khoang #03 lúc 01:43 để chuẩn bị lệnh chuyển 500 BTC sang `lotus-bridge-mixer.xyz`!',
          inspected: false,
          linkedSuspectId: 'suspect-bach',
          iocExtracted: 'lotus-bridge-mixer.xyz'
        },
        {
          id: 'ev-syringe-case',
          name: 'Vỏ Ống Tiêm Thuốc Mê & Vết Xước Nhẫn Bạch Kim',
          category: 'CHEMICAL_LAB',
          icon: '💉',
          locationFound: 'Thùng rác ẩn dưới bồn rửa Khoang VIP #01',
          initialSummary:
            'Ống tiêm chứa Propofol đậm đặc đã qua sử dụng, thân ống bị lau sạch vân tay.',
          deepForensicResult:
            '🔬 [PHÁP Y VẬT CHỨNG]: Trên cổ thủy tinh có vết xước vi mô hình răng cưa trùng khớp 100% với họa tiết chiếc nhẫn bạch kim mà CFO Trịnh Gia Bạch đeo ở ngón cái tay phải.',
          inspected: false,
          linkedSuspectId: 'suspect-lena',
          iocExtracted: '0987112309'
        },
        {
          id: 'ev-corridor-switch',
          name: 'Bảng Điều Khiển Điện Chiếu Sáng Hành Lang Toa VIP',
          category: 'TIMELINE_CHECK',
          icon: '💡',
          locationFound: 'Buồng trực Trưởng toa đầu Toa VIP #01',
          initialSummary:
            'Đèn hành lang và đèn hồng ngoại camera bị ngắt thủ công lúc 01:30.',
          deepForensicResult:
            '🔬 [XÁC MINH HIỆN TRƯỜNG]: Tìm thấy 5 tờ 100 USD mới cứng có số seri liền kề với xấp tiền trong ví của Trịnh Gia Bạch, chứng minh hành vi mua chuộc tắt đèn có chủ đích trước khi gây án.',
          inspected: false,
          linkedSuspectId: 'suspect-tung',
          iocExtracted: '103.148.204.91'
        }
      ],
      timeline: [
        { time: '21:45', event: 'Gia Bạch tiếp cận túi y tế của y tá Lê Na tại toa nhà hàng để lấy trộm ống thuốc mê.' },
        { time: '01:25', event: 'Gia Bạch đưa 500 USD cho Trưởng toa Tùng để tắt toàn bộ đèn hành lang toa VIP.' },
        { time: '01:38', event: 'Tàu đi vào hầm Hải Vân; Gia Bạch lẻn vào khoang Marcus Vũ tiêm thuốc mê và lấy ví lạnh 500 BTC.' },
        { time: '01:43', event: 'Cảm biến IoT bắt được sóng Bluetooth của ví lạnh Ledger phát ra từ khoang #03 của Gia Bạch.' }
      ]
    }
  ];
}

// Bộ sinh vụ án ngẫu nhiên (Procedural Mystery Engine) đảm bảo 100% suy luận logic
function generateProceduralCase() {
  const caseNum = Math.floor(200 + Math.random() * 799);
  const scenarios = [
    {
      title: `Bí Ẩn Đêm Đấu Giá Cổ Vật Số #${caseNum}`,
      location: 'Phòng Trưng Bày Ngầm Sapphire — Biệt Thự Cổ Hồ Tây',
      victimName: 'Nhà Sưu Tập Hoàng Bách (52 tuổi)',
      victimRole: 'Chủ sở hữu Bản thảo Mật mã Nguyễn Ánh & Khóa Ví Nghệ Thuật',
      causeOfDeath: 'Ngạt khí CO2 trong buồng bảo quản cổ vật bị khóa cưỡng bức từ hệ thống SmartHome.',
      motivePool: 'Đánh tráo bản thảo gốc và rút 1.2 triệu USDT qua hợp đồng thông minh khẩn cấp.'
    },
    {
      title: `Vụ Án Đài Quan Sát Vệ Tinh Đám Mây #${caseNum}`,
      location: 'Đài Viễn Thám Độ Cao 1.500m — Đỉnh Ba Vì',
      victimName: 'Kỹ Sư Trưởng Phan Quốc Huy (43 tuổi)',
      victimRole: 'Chuyên gia Điều khiển Quỹ đạo Vệ tinh Viễn thông',
      causeOfDeath: 'Bị phóng điện cao áp từ bảng điều khiển ăng-ten đã bị can thiệp rơ-le bảo vệ.',
      motivePool: 'Che giấu việc cho thuê trái phép băng tần vệ tinh cho mạng lưới máy chủ C2 quốc tế.'
    }
  ];

  const picked = scenarios[Math.floor(Math.random() * scenarios.length)];
  const c2Ip = `194.${Math.floor(20 + Math.random() * 200)}.${Math.floor(10 + Math.random() * 200)}.${Math.floor(10 + Math.random() * 240)}`;
  const burnerPhone = `09${Math.floor(10000000 + Math.random() * 89999999)}`;
  const darkDomain = `shadow-vault-${caseNum}.top`;

  return {
    id: `case-proc-${caseNum}`,
    code: `NOIR-2026-${caseNum}`,
    title: picked.title,
    location: picked.location,
    timeOfIncident: '00:20 Đêm Sương Mù',
    victim: {
      name: picked.victimName,
      role: picked.victimRole,
      causeOfDeath: picked.causeOfDeath
    },
    summary: `Hệ thống an ninh ghi nhận sự cố tử vong bất thường của ${picked.victimName} lúc 00:20. Mọi lối thoát vật lý đều khóa kín, nhưng nhật ký hệ thống điều khiển trung tâm có dấu hiệu bị chỉnh sửa mốc thời gian (Timestamp Manipulation).`,
    culpritId: 'suspect-p1',
    correctMotive: picked.motivePool,
    decisiveEvidenceId: 'ev-proc-1',
    iocs: [c2Ip, darkDomain, burnerPhone],
    suspects: [
      {
        id: 'suspect-p1',
        name: 'Kiều Minh Tuấn (33 tuổi)',
        role: 'Kiến trúc sư Hệ thống Tự động hóa SmartHome',
        avatar: '🕶️',
        initialAlibi: 'Tôi đang ngồi chỉnh sửa bản vẽ kỹ thuật ở phòng điều hành phụ tầng 1 lúc 00:20.',
        trueSecret: `Đã gửi gói tin MQTT giả mạo từ điện thoại phụ (${burnerPhone}) để khóa buồng bảo quản và xóa log.`,
        baseBpm: 82,
        stressLevel: 42,
        alibiBroken: false,
        contradictingEvidenceId: 'ev-proc-1',
        interrogationResponses: {
          PRESS_ALIBI: 'Máy tính của tôi ở tầng 1 vẫn đang mở phần mềm AutoCAD lúc 00:20, các anh có thể kiểm tra!',
          GOOD_COP: 'Hệ thống SmartHome này do chính tay tôi viết firmware, bình thường không bao giờ tự khóa khi có người bên trong.',
          POLYGRAPH_TRAP: 'Đừng nhìn vào nhịp tim của tôi, ai bị thẩm vấn lúc nửa đêm mà chẳng căng thẳng!',
          BROKEN: `💥 [NGOẠI PHẠM SỤP ĐỔ] Các anh đã khôi phục được bộ nhớ đệm MQTT Broker?! Đúng... chính tôi đã dùng số điện thoại rác ${burnerPhone} gửi lệnh khóa cưỡng bức lúc 00:18!`
        }
      },
      {
        id: 'suspect-p2',
        name: 'Trần Thanh Hà (30 tuổi)',
        role: 'Chuyên viên Kiểm định Bảo hiểm & Pháp lý',
        avatar: '👩‍💼',
        initialAlibi: 'Tôi đang gọi điện thoại video với đối tác ở sảnh chính lúc xảy ra vụ việc.',
        trueSecret: 'Đang giữ bản hợp đồng bảo hiểm nhân thọ trị giá lớn nhưng không biết kỹ thuật can thiệp rơ-le.',
        baseBpm: 75,
        stressLevel: 30,
        alibiBroken: false,
        contradictingEvidenceId: 'ev-proc-2',
        interrogationResponses: {
          PRESS_ALIBI: 'Cuộc gọi video của tôi được ghi âm trên máy chủ công ty bảo hiểm từ 00:05 đến 00:30!',
          GOOD_COP: 'Lúc 00:15 tôi thấy anh Tuấn đứng bấm một chiếc điện thoại lạ màu đen ngoài hành lang chứ không phải ngồi ở bàn vẽ.',
          POLYGRAPH_TRAP: 'Tôi hoàn toàn vô tội, máy đo nói dối sẽ chứng minh điều đó!',
          BROKEN: '🔍 [XÁC NHẬN LỜI KHAI] Nhật ký cuộc gọi xác nhận cô Hà ở sảnh chính và nhìn thấy Kiều Minh Tuấn cầm chiếc điện thoại burner ngoài hành lang lúc 00:15!'
        }
      }
    ],
    evidence: [
      {
        id: 'ev-proc-1',
        name: 'Bộ nhớ đệm MQTT Broker & Gói tin Lệnh Cưỡng Bức',
        category: 'DIGITAL_FORENSICS',
        icon: '📡',
        locationFound: 'Máy chủ điều khiển trung tâm (Tủ Rack tầng hầm)',
        initialSummary: 'File log chính bị xóa trắng từ 00:10 đến 00:25, nhưng phân vùng swap vẫn còn mảnh dữ liệu.',
        deepForensicResult: `🔬 [PHÁP Y SỐ]: Khôi phục RAM dump phát hiện lệnh OVERRIDE_LOCK được gửi lúc 00:18 từ thiết bị mang SIM ${burnerPhone} kết nối qua máy chủ C2 ${c2Ip} (${darkDomain}), trùng khớp với khóa SSH trên laptop của Kiều Minh Tuấn!`,
        inspected: false,
        linkedSuspectId: 'suspect-p1',
        iocExtracted: c2Ip
      },
      {
        id: 'ev-proc-2',
        name: 'Bản ghi Trạm Thu Phát Sóng Nội Bộ (Femtocell Log)',
        category: 'TIMELINE_CHECK',
        icon: '📱',
        locationFound: 'Trạm phát sóng di động trong tòa nhà',
        initialSummary: 'Có một thuê bao lạ chỉ bật nguồn đúng 4 phút trong đêm xảy ra án mạng.',
        deepForensicResult: `🔬 [PHÁP Y VIỄN THÔNG]: Thuê bao ${burnerPhone} định vị ngay tại hành lang tầng 1 (vị trí Kiều Minh Tuấn đứng lúc 00:15 theo lời khai của nhân chứng Hà).`,
        inspected: false,
        linkedSuspectId: 'suspect-p2',
        iocExtracted: burnerPhone
      }
    ],
    timeline: [
      { time: '00:15', event: 'Nhân chứng Hà thấy Kiều Minh Tuấn dùng điện thoại lạ ngoài hành lang tầng 1.' },
      { time: '00:18', event: `Gói tin MQTT OVERRIDE_LOCK được phát từ thuê bao ${burnerPhone} qua IP ${c2Ip}.` },
      { time: '00:20', event: 'Nạn nhân tử vong trong khu vực bị khóa cưỡng bức; log bề mặt bị xóa.' }
    ]
  };
}

let casesCatalog = createPresetCases();
let activeCaseId = casesCatalog[0].id;
let interrogationLogs = [
  {
    time: new Date().toLocaleTimeString('vi-VN'),
    speaker: 'HỆ THỐNG PHÁP Y NOIR',
    suspectName: 'Toàn bộ hồ sơ',
    tactic: 'INIT',
    text: 'Đã khởi tạo hồ sơ hiện trường. Hãy khám nghiệm vật chứng để mở khóa dữ liệu Pháp y Số trước khi thẩm vấn nghi phạm!',
    bpm: 76,
    gsr: 24,
    deceptionProb: 12,
    alibiBroken: false
  }
];
let latestAccusationResult = null;
let osintPushHistory = [];

function getActiveCase() {
  return casesCatalog.find((c) => c.id === activeCaseId) || casesCatalog[0];
}

// ============================================================================
// 2. XỬ LÝ NGHIỆP VỤ: KHÁM NGHIỆM, THẨM VẤN POLYGRAPH, BẺ GÃY NGOẠI PHẠM & PHÁ ÁN
// ============================================================================

function inspectEvidence(evidenceId) {
  const currentCase = getActiveCase();
  const ev = currentCase.evidence.find((e) => e.id === evidenceId);
  if (!ev) throw new Error('Không tìm thấy vật chứng cần giám định');

  ev.inspected = true;
  interrogationLogs.unshift({
    time: new Date().toLocaleTimeString('vi-VN'),
    speaker: 'PHÒNG LAB PHÁP Y SỐ',
    suspectName: ev.name,
    tactic: 'FORENSIC_XRAY',
    text: ev.deepForensicResult,
    bpm: 72,
    gsr: 18,
    deceptionProb: 5,
    alibiBroken: false
  });
  if (interrogationLogs.length > 40) interrogationLogs.length = 40;
  return ev;
}

function interrogateSuspect({ suspectId, tactic = 'PRESS_ALIBI', evidenceId = null, customQuestion = '' }) {
  const currentCase = getActiveCase();
  const suspect = currentCase.suspects.find((s) => s.id === suspectId);
  if (!suspect) throw new Error('Không tìm thấy nghi phạm');

  const isCulprit = suspect.id === currentCase.culpritId;
  let responseText = '';
  let bpm = suspect.baseBpm;
  let gsr = suspect.stressLevel;
  let deceptionProb = isCulprit ? 64 : 22;
  let brokeNow = false;

  if (tactic === 'PRESENT_EVIDENCE' && evidenceId) {
    const ev = currentCase.evidence.find((e) => e.id === evidenceId);
    if (!ev) throw new Error('Vật chứng không hợp lệ');

    if (!ev.inspected) {
      // Tự động giám định nếu người dùng đưa thẳng bằng chứng ra
      ev.inspected = true;
    }

    if (evidenceId === suspect.contradictingEvidenceId) {
      suspect.alibiBroken = true;
      suspect.stressLevel = Math.min(99, suspect.stressLevel + 45);
      suspect.baseBpm = isCulprit ? 138 : 96;
      bpm = suspect.baseBpm;
      gsr = suspect.stressLevel;
      deceptionProb = isCulprit ? 98 : 15;
      brokeNow = true;
      responseText = suspect.interrogationResponses.BROKEN;
    } else {
      bpm = suspect.baseBpm + 10;
      gsr = Math.min(95, suspect.stressLevel + 12);
      deceptionProb = isCulprit ? 72 : 25;
      responseText = `Vật chứng "${ev.name}" này không hề mâu thuẫn trực tiếp với lời khai của tôi! Các anh đang suy diễn đấy!`;
    }
  } else if (tactic === 'POLYGRAPH_TRAP') {
    bpm = suspect.baseBpm + (isCulprit ? 34 : 14);
    gsr = Math.min(96, suspect.stressLevel + (isCulprit ? 35 : 15));
    deceptionProb = isCulprit ? 89 : 28;
    responseText = suspect.interrogationResponses.POLYGRAPH_TRAP;
  } else if (tactic === 'GOOD_COP') {
    bpm = Math.max(65, suspect.baseBpm - 4);
    gsr = Math.max(20, suspect.stressLevel - 5);
    deceptionProb = isCulprit ? 58 : 14;
    responseText = suspect.interrogationResponses.GOOD_COP;
  } else {
    bpm = suspect.baseBpm + (isCulprit ? 22 : 8);
    gsr = Math.min(92, suspect.stressLevel + (isCulprit ? 20 : 8));
    deceptionProb = isCulprit ? 78 : 24;
    responseText = suspect.interrogationResponses.PRESS_ALIBI;
  }

  if (customQuestion && customQuestion.trim()) {
    responseText = `[Trả lời câu hỏi "${customQuestion.trim()}"]: ${responseText}`;
  }

  const entry = {
    id: crypto.randomUUID(),
    time: new Date().toLocaleTimeString('vi-VN'),
    speaker: suspect.name,
    suspectId: suspect.id,
    suspectName: suspect.name,
    tactic,
    evidenceId,
    text: responseText,
    bpm,
    gsr,
    voiceTremorHz: Number((bpm / 11.5).toFixed(1)),
    deceptionProb,
    alibiBroken: brokeNow || suspect.alibiBroken
  };

  interrogationLogs.unshift(entry);
  if (interrogationLogs.length > 40) interrogationLogs.length = 40;
  return entry;
}

function submitAccusation({ suspectId, evidenceId, notes = '' }) {
  const currentCase = getActiveCase();
  const suspect = currentCase.suspects.find((s) => s.id === suspectId);
  if (!suspect) throw new Error('Vui lòng chọn nghi phạm để phê chuẩn lệnh bắt giữ');

  const isCorrectCulprit = suspectId === currentCase.culpritId;
  const isCorrectEvidence = !evidenceId || evidenceId === currentCase.decisiveEvidenceId;
  const inspectedCount = currentCase.evidence.filter((e) => e.inspected).length;
  const brokenCount = currentCase.suspects.filter((s) => s.alibiBroken).length;

  const solved = isCorrectCulprit && isCorrectEvidence;
  let score = 0;
  if (isCorrectCulprit) score += 60;
  if (isCorrectEvidence) score += 25;
  score += Math.min(15, inspectedCount * 4 + brokenCount * 5);

  const rank = score >= 95 ? 'S+ (Thám Tử Huyền Thoại)' : score >= 80 ? 'A (Điều Tra Viên Cao Cấp)' : score >= 55 ? 'B (Đúng Hướng)' : 'C (Cần Bổ Sung Bằng Chứng)';

  latestAccusationResult = {
    solved,
    score,
    rank,
    accusedSuspect: suspect.name,
    trueCulpritId: currentCase.culpritId,
    decisiveEvidenceId: currentCase.decisiveEvidenceId,
    motive: currentCase.correctMotive,
    notes,
    verdictText: solved
      ? `🎉 PHÁ ÁN THÀNH CÔNG! Bạn đã vạch trần hung thủ ${suspect.name} cùng bằng chứng thép và động cơ: "${currentCase.correctMotive}".`
      : `⚠️ CHƯA ĐỦ CĂN CỨ KẾT TỘI! Nghi phạm hoặc vật chứng quyết định chưa khớp với chuỗi logic hiện trường. Hãy giám định kỹ các dấu vết Pháp y Số và bẻ gãy bằng chứng ngoại phạm!`
  };

  return latestAccusationResult;
}

function pushCaseIocsToOsint() {
  return new Promise((resolve) => {
    const currentCase = getActiveCase();
    const payloadStr = JSON.stringify({
      text: `NoirDetective Case ${currentCase.code} (${currentCase.title}): ${currentCase.iocs.join(' ')}`,
      pushToGraph: true,
      sourceTitle: `NoirDetective_${currentCase.code}`
    });

    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: 4090,
        path: '/api/osint/ioc',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payloadStr, 'utf8')
        },
        timeout: 3500
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          let parsed = null;
          try {
            parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          } catch (_) {}
          const event = {
            time: new Date().toLocaleTimeString('vi-VN'),
            caseCode: currentCase.code,
            iocs: currentCase.iocs,
            osintOnline: res.statusCode < 400,
            pushedCount: currentCase.iocs.length,
            osintResponse: parsed
          };
          osintPushHistory.unshift(event);
          resolve(event);
        });
      }
    );

    req.on('error', () => {
      const event = {
        time: new Date().toLocaleTimeString('vi-VN'),
        caseCode: currentCase.code,
        iocs: currentCase.iocs,
        osintOnline: false,
        pushedCount: currentCase.iocs.length,
        note: 'Đã đóng gói IOC Pháp y Số (OmniTrace Port 4090 hiện đang tắt, có thể bật từ NexusHub để đồng bộ trực tiếp).'
      };
      osintPushHistory.unshift(event);
      resolve(event);
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({
        time: new Date().toLocaleTimeString('vi-VN'),
        caseCode: currentCase.code,
        iocs: currentCase.iocs,
        osintOnline: false,
        pushedCount: currentCase.iocs.length
      });
    });

    req.write(payloadStr);
    req.end();
  });
}

// ============================================================================
// 3. GIAO DIỆN WEB TƯƠNG TÁC FILM-NOIR CYBERPUNK (HTML5 + CANVAS POLYGRAPH)
// ============================================================================

function renderHtmlPage() {
  return `<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>NoirDetective — Trung Tâm Điều Tra Hiện Trường, Pháp Y Số & Thẩm Vấn (Port 4130)</title>
  <style>
    :root {
      --bg: #080b12;
      --panel: #101624;
      --panel-2: #161f33;
      --border: #263452;
      --amber: #f59e0b;
      --crimson: #ef4444;
      --cyan: #06b6d4;
      --emerald: #10b981;
      --text: #f1f5f9;
      --muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: radial-gradient(circle at top right, #172036 0%, #080b12 65%);
      color: var(--text);
      min-height: 100vh;
      padding: 18px 24px 40px;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 14px;
      padding: 16px 20px;
      background: rgba(16, 22, 36, 0.92);
      border: 1px solid var(--border);
      border-left: 4px solid var(--amber);
      border-radius: 12px;
      margin-bottom: 18px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.45);
    }
    .title-wrap h1 {
      font-size: 21px;
      display: flex;
      align-items: center;
      gap: 10px;
      color: #fff;
    }
    .badge-port {
      font-size: 12px;
      background: rgba(245, 158, 11, 0.18);
      color: #fbbf24;
      border: 1px solid rgba(245, 158, 11, 0.4);
      padding: 3px 9px;
      border-radius: 999px;
    }
    .subtitle {
      font-size: 13px;
      color: var(--muted);
      margin-top: 4px;
    }
    .top-controls {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      align-items: center;
    }
    select, input, button {
      font-family: inherit;
      font-size: 13px;
      border-radius: 8px;
    }
    select, input {
      background: #0b101b;
      color: var(--text);
      border: 1px solid var(--border);
      padding: 8px 12px;
    }
    .btn {
      cursor: pointer;
      border: 1px solid transparent;
      padding: 8px 14px;
      font-weight: 600;
      transition: all 0.15s ease;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .btn-amber { background: #d97706; color: #fff; }
    .btn-amber:hover { background: #f59e0b; }
    .btn-cyan { background: #0891b2; color: #fff; }
    .btn-cyan:hover { background: #06b6d4; }
    .btn-crimson { background: #dc2626; color: #fff; }
    .btn-crimson:hover { background: #ef4444; }
    .btn-emerald { background: #059669; color: #fff; }
    .btn-emerald:hover { background: #10b981; }
    .btn-ghost {
      background: rgba(255,255,255,0.05);
      color: var(--text);
      border-color: var(--border);
    }
    .btn-ghost:hover { background: rgba(255,255,255,0.12); }

    .case-banner {
      background: linear-gradient(135deg, rgba(22,31,51,0.95), rgba(15,23,42,0.92));
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px 20px;
      margin-bottom: 18px;
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 16px;
    }
    .case-meta-pills {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin: 8px 0;
    }
    .pill {
      font-size: 11.5px;
      padding: 3px 10px;
      border-radius: 999px;
      background: rgba(6, 182, 212, 0.14);
      color: #67e8f9;
      border: 1px solid rgba(6, 182, 212, 0.3);
    }
    .victim-box {
      background: rgba(239, 68, 68, 0.09);
      border: 1px solid rgba(239, 68, 68, 0.35);
      border-radius: 10px;
      padding: 12px 14px;
      font-size: 12.5px;
    }
    .victim-box strong { color: #fca5a5; display: block; margin-bottom: 4px; }

    .workspace-grid {
      display: grid;
      grid-template-columns: 1.1fr 1.25fr 1fr;
      gap: 16px;
    }
    @media (max-width: 1200px) {
      .workspace-grid { grid-template-columns: 1fr; }
      .case-banner { grid-template-columns: 1fr; }
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .panel h2 {
      font-size: 15px;
      color: #fbbf24;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border);
      padding-bottom: 8px;
    }
    .card-item {
      background: var(--panel-2);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .card-item.broken {
      border-color: var(--crimson);
      box-shadow: 0 0 12px rgba(239, 68, 68, 0.25);
    }
    .card-item.inspected {
      border-color: var(--emerald);
    }
    .forensic-output {
      background: rgba(16, 185, 129, 0.11);
      border-left: 3px solid var(--emerald);
      padding: 8px 10px;
      border-radius: 6px;
      font-size: 12px;
      color: #a7f3d0;
      line-height: 1.45;
    }
    .polygraph-box {
      background: #060911;
      border: 1px solid #1e293b;
      border-radius: 10px;
      padding: 10px;
    }
    canvas#polygraph-canvas {
      width: 100%;
      height: 110px;
      display: block;
    }
    .poly-metrics {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 8px;
      margin-top: 8px;
      text-align: center;
    }
    .poly-stat {
      background: rgba(255,255,255,0.03);
      padding: 6px;
      border-radius: 6px;
      font-size: 11.5px;
    }
    .poly-stat strong { display: block; font-size: 15px; margin-top: 2px; }
    .log-list {
      max-height: 290px;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .log-item {
      background: #0b101c;
      border-left: 3px solid var(--cyan);
      padding: 9px 11px;
      border-radius: 6px;
      font-size: 12.5px;
      line-height: 1.45;
    }
    .log-item.broken-log {
      border-left-color: var(--crimson);
      background: rgba(239, 68, 68, 0.12);
    }
    .verdict-banner {
      padding: 12px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 600;
      line-height: 1.45;
    }
    .verdict-banner.ok {
      background: rgba(16, 185, 129, 0.18);
      border: 1px solid var(--emerald);
      color: #6ee7b7;
    }
    .verdict-banner.warn {
      background: rgba(245, 158, 11, 0.16);
      border: 1px solid var(--amber);
      color: #fde68a;
    }
    * {
      scrollbar-width: thin;
      scrollbar-color: rgba(6, 182, 212, 0.45) rgba(8, 11, 18, 0.9);
    }
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: rgba(8, 11, 18, 0.9); border-radius: 999px; }
    ::-webkit-scrollbar-thumb { background: linear-gradient(180deg, #06b6d4, #f59e0b); border-radius: 999px; }
    .scene-stage-wrap {
      position: relative;
      border-radius: 16px;
      overflow: hidden;
      border: 1px solid rgba(6, 182, 212, 0.45);
      background: #050811;
      margin-bottom: 18px;
      box-shadow: 0 18px 48px rgba(0, 0, 0, 0.78), 0 0 24px rgba(6, 182, 212, 0.14);
    }
    .scene-visor-bar {
      position: absolute;
      top: 12px;
      left: 14px;
      z-index: 10;
      display: flex;
      gap: 6px;
      padding: 4px;
      border-radius: 11px;
      background: rgba(5, 9, 20, 0.88);
      border: 1px solid rgba(6, 182, 212, 0.35);
      backdrop-filter: blur(10px);
    }
    .visor-mode-btn {
      padding: 5px 11px;
      border-radius: 8px;
      border: 1px solid transparent;
      background: transparent;
      color: #94a3b8;
      font-size: 12px;
      font-weight: 700;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .visor-mode-btn.active {
      background: rgba(6, 182, 212, 0.24);
      border-color: #06b6d4;
      color: #f8fafc;
      box-shadow: 0 0 12px rgba(6, 182, 212, 0.35);
    }
    .scene-hud-hint {
      position: absolute;
      top: 14px;
      right: 14px;
      z-index: 10;
      padding: 5px 12px;
      border-radius: 999px;
      background: rgba(5, 9, 20, 0.86);
      border: 1px solid rgba(245, 158, 11, 0.45);
      color: #fde68a;
      font-size: 11.5px;
      font-weight: 700;
    }
    #noirSceneCanvas {
      width: 100%;
      height: auto;
      display: block;
      cursor: crosshair;
    }
  </style>
</head>
<body>
  <header>
    <div class="title-wrap">
      <h1>
        🕵️‍♂️ NoirDetective
        <span class="badge-port">2.5D Crime Scene, Digital Forensics &amp; Polygraph • Port 4130</span>
      </h1>
      <p class="subtitle">
        Khám nghiệm hiện trường 2.5D • Giám định Pháp y Số • Máy đo nói dối Polygraph thời gian thực • Bẻ gãy ngoại phạm &amp; Liên thông OmniTrace OSINT
      </p>
    </div>
    <div class="top-controls">
      <select id="sel-case"></select>
      <button class="btn btn-amber" id="btn-gen-case">🎲 Sinh Vụ Án Ngẫu Nhiên Mới</button>
      <button class="btn btn-cyan" id="btn-push-osint">🕸️ Đẩy IOC Sang OmniTrace OSINT (4090)</button>
    </div>
  </header>

  <section class="case-banner" id="case-banner"></section>

  <!-- SÂN KHẤU HIỆN TRƯỜNG 2.5D TƯƠNG TÁC 60FPS -->
  <section class="scene-stage-wrap">
    <div class="scene-visor-bar">
      <button class="visor-mode-btn active" id="vbtn-NORMAL" onclick="setNoirVisor('NORMAL')">🔦 [1] Đèn Pin Chuẩn</button>
      <button class="visor-mode-btn" id="vbtn-UV" onclick="setNoirVisor('UV')">🟣 [2] Tia Cực Tím UV</button>
      <button class="visor-mode-btn" id="vbtn-CYBER" onclick="setNoirVisor('CYBER')">📡 [3] Quét Mạng RFID/IoT</button>
    </div>
    <div class="scene-hud-hint">🖱️ Click Vật Chứng Bát Giác để Thám Tử tới Giám Định • Phím 1•2•3 đổi Kính Pháp Y</div>
    <canvas id="noirSceneCanvas" width="960" height="330"></canvas>
  </section>

  <main class="workspace-grid">
    <!-- CỘT 1: PHÒNG LAB KHÁM NGHIỆM VẬT CHỨNG & DÒNG THỜI GIAN -->
    <section class="panel">
      <h2>
        <span>🔬 1. Vật Chứng Hiện Trường &amp; Pháp Y Số</span>
        <span style="font-size:11.5px;color:var(--muted);" id="ev-progress">0/0 đã giám định</span>
      </h2>
      <div id="evidence-list" style="display:flex;flex-direction:column;gap:10px;"></div>

      <h2 style="margin-top:8px;">⏱️ Chuỗi Thời Gian Hiện Trường (Timeline)</h2>
      <div id="timeline-list" style="display:flex;flex-direction:column;gap:6px;font-size:12.5px;"></div>
    </section>

    <!-- CỘT 2: BUỒNG THẨM VẤN NGHI PHẠM & MÁY ĐO NÓI DỐI POLYGRAPH -->
    <section class="panel">
      <h2>
        <span>🎙️ 2. Buồng Thẩm Vấn &amp; Máy Đo Nói Dối Polygraph</span>
        <span style="font-size:11.5px;color:#fca5a5;">⚡ Alibi Breaker</span>
      </h2>

      <div class="polygraph-box">
        <div style="display:flex;justify-content:space-between;font-size:11.5px;color:var(--muted);margin-bottom:4px;">
          <span id="poly-subject-label">Đang theo dõi sinh trắc: Chưa chọn nghi phạm</span>
          <span style="color:#38bdf8;">LIVE BIOMETRIC TELEMETRY</span>
        </div>
        <canvas id="polygraph-canvas" width="520" height="110"></canvas>
        <div class="poly-metrics">
          <div class="poly-stat">
            <span>❤️ Nhịp tim (BPM)</span>
            <strong id="stat-bpm" style="color:#f87171;">76 BPM</strong>
          </div>
          <div class="poly-stat">
            <span>💧 Điện trở da (GSR)</span>
            <strong id="stat-gsr" style="color:#38bdf8;">24 μS</strong>
          </div>
          <div class="poly-stat">
            <span>🚨 Xác suất nói dối</span>
            <strong id="stat-deception" style="color:#fbbf24;">12%</strong>
          </div>
        </div>
      </div>

      <div id="suspects-list" style="display:flex;flex-direction:column;gap:10px;"></div>

      <h2>📜 Nhật Ký Thẩm Vấn &amp; Đối Chất</h2>
      <div class="log-list" id="interrogation-logs"></div>
    </section>

    <!-- CỘT 3: BẢNG KẾT LUẬN PHÁ ÁN & LỆNH BẮT GIỮ -->
    <section class="panel">
      <h2>⚖️ 3. Bàn Kết Luận Phá Án &amp; Phê Chuẩn Lệnh Bắt</h2>
      <p style="font-size:12.5px;color:var(--muted);line-height:1.45;">
        Sau khi giám định vật chứng và bẻ gãy lời khai ngoại phạm, hãy chỉ định <strong>Hung thủ thực sự</strong> kèm <strong>Bằng chứng quyết định</strong> để lập hồ sơ khởi tố:
      </p>

      <label style="font-size:12px;color:#cbd5e1;">Chỉ định Hung thủ:</label>
      <select id="accuse-suspect"></select>

      <label style="font-size:12px;color:#cbd5e1;">Bằng chứng Thép quyết định:</label>
      <select id="accuse-evidence"></select>

      <label style="font-size:12px;color:#cbd5e1;">Ghi chú suy luận của Thám tử:</label>
      <input type="text" id="accuse-notes" placeholder="Nhập tóm tắt thủ đoạn gây án..." />

      <button class="btn btn-crimson" id="btn-submit-accuse" style="justify-content:center;padding:11px;">
        🚨 PHÊ CHUẨN LỆNH BẮT GIỮ &amp; CÔNG BỐ SỰ THẬT
      </button>

      <div id="verdict-box"></div>

      <h2 style="margin-top:8px;">🕸️ Dấu Vết Số (IOC) Liên Thông OSINT</h2>
      <div id="ioc-box" style="font-size:12px;color:#94a3b8;display:flex;flex-direction:column;gap:6px;"></div>
    </section>
  </main>

  <script>
    let appState = null;
    let currentPoly = { bpm: 76, gsr: 24, deceptionProb: 12, subject: 'Sẵn sàng' };
    let waveTick = 0;

    function esc(s) {
      return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    async function api(path, method = 'GET', body = null) {
      const opts = { method, headers: {} };
      if (body) {
        opts.headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(body);
      }
      const res = await fetch(path, opts);
      return res.json();
    }

    function renderAll() {
      if (!appState || !appState.activeCase) return;
      const c = appState.activeCase;

      const selCase = document.getElementById('sel-case');
      selCase.innerHTML = appState.casesCatalog.map(item =>
        \`<option value="\${esc(item.id)}" \${item.id === c.id ? 'selected' : ''}>📂 [\${esc(item.code)}] \${esc(item.title)}</option>\`
      ).join('');

      document.getElementById('case-banner').innerHTML = \`
        <div>
          <div style="font-size:12px;color:#fbbf24;font-weight:700;">HỒ SƠ VỤ ÁN: \${esc(c.code)}</div>
          <h2 style="font-size:20px;margin:4px 0;color:#fff;">\${esc(c.title)}</h2>
          <div class="case-meta-pills">
            <span class="pill">📍 \${esc(c.location)}</span>
            <span class="pill">🕒 \${esc(c.timeOfIncident)}</span>
          </div>
          <p style="font-size:13px;color:#cbd5e1;line-height:1.5;margin-top:8px;">\${esc(c.summary)}</p>
        </div>
        <div class="victim-box">
          <strong>🩸 NẠN NHÂN: \${esc(c.victim.name)}</strong>
          <div style="color:#e2e8f0;margin-bottom:6px;">Chức vụ: \${esc(c.victim.role)}</div>
          <div style="color:#fecaca;">Biên bản khám nghiệm: \${esc(c.victim.causeOfDeath)}</div>
        </div>
      \`;

      const inspectedCount = c.evidence.filter(e => e.inspected).length;
      document.getElementById('ev-progress').textContent = \`\${inspectedCount}/\${c.evidence.length} đã giám định\`;

      document.getElementById('evidence-list').innerHTML = c.evidence.map(ev => \`
        <div class="card-item \${ev.inspected ? 'inspected' : ''}">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px;">
            <div>
              <strong style="font-size:13.5px;color:#fff;">\${ev.icon} \${esc(ev.name)}</strong>
              <div style="font-size:11.5px;color:var(--muted);">Nơi thu giữ: \${esc(ev.locationFound)}</div>
            </div>
            <button class="btn \${ev.inspected ? 'btn-ghost' : 'btn-emerald'}" style="padding:5px 10px;font-size:11.5px;" onclick="inspectEv('\${esc(ev.id)}')">
              \${ev.inspected ? '✅ Đã Giám Định' : '🔍 Giám Định Pháp Y'}
            </button>
          </div>
          <p style="font-size:12.5px;color:#cbd5e1;">\${esc(ev.initialSummary)}</p>
          \${ev.inspected ? \`<div class="forensic-output">\${esc(ev.deepForensicResult)}</div>\` : ''}
        </div>
      \`).join('');

      document.getElementById('timeline-list').innerHTML = c.timeline.map(t => \`
        <div style="padding:7px 10px;background:#0b101c;border-radius:6px;border-left:3px solid var(--amber);">
          <strong style="color:#fbbf24;">[\${esc(t.time)}]</strong> \${esc(t.event)}
        </div>
      \`).join('');

      const evOptions = c.evidence.map(ev => \`<option value="\${esc(ev.id)}">\${ev.icon} \${esc(ev.name)}</option>\`).join('');

      document.getElementById('suspects-list').innerHTML = c.suspects.map(s => \`
        <div class="card-item \${s.alibiBroken ? 'broken' : ''}">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <div>
              <strong style="font-size:14px;">\${s.avatar} \${esc(s.name)}</strong>
              <div style="font-size:11.5px;color:var(--muted);">\${esc(s.role)}</div>
            </div>
            <span class="pill" style="\${s.alibiBroken ? 'background:rgba(239,68,68,0.2);color:#fca5a5;border-color:#ef4444;' : ''}">
              \${s.alibiBroken ? '💥 ĐÃ VỠ NGOẠI PHẠM' : \`❤️ \${s.baseBpm} BPM\`}
            </span>
          </div>
          <div style="font-size:12px;background:rgba(255,255,255,0.03);padding:8px;border-radius:6px;color:#e2e8f0;">
            <strong>Lời khai ngoại phạm:</strong> "\${esc(s.initialAlibi)}"
          </div>
          <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;">
            <button class="btn btn-ghost" style="padding:5px 9px;font-size:11.5px;" onclick="askSuspect('\${esc(s.id)}','PRESS_ALIBI')">😠 Truy vấn Alibi</button>
            <button class="btn btn-ghost" style="padding:5px 9px;font-size:11.5px;" onclick="askSuspect('\${esc(s.id)}','GOOD_COP')">🤝 Khai thác mềm</button>
            <button class="btn btn-amber" style="padding:5px 9px;font-size:11.5px;" onclick="askSuspect('\${esc(s.id)}','POLYGRAPH_TRAP')">⚡ Gài bẫy Polygraph</button>
          </div>
          <div style="display:flex;gap:6px;align-items:center;margin-top:2px;">
            <select id="ev-for-\${esc(s.id)}" style="flex:1;padding:5px 8px;font-size:11.5px;">\${evOptions}</select>
            <button class="btn btn-crimson" style="padding:5px 10px;font-size:11.5px;" onclick="presentEv('\${esc(s.id)}')">💥 Đập Bằng Chứng</button>
          </div>
        </div>
      \`).join('');

      document.getElementById('interrogation-logs').innerHTML = (appState.interrogationLogs || []).map(l => \`
        <div class="log-item \${l.alibiBroken ? 'broken-log' : ''}">
          <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--muted);margin-bottom:3px;">
            <span><strong>\${esc(l.speaker)}</strong> (\${esc(l.tactic)})</span>
            <span>[\${esc(l.time)}] ❤️ \${l.bpm} BPM • 🚨 Dối: \${l.deceptionProb}%</span>
          </div>
          <div>\${esc(l.text)}</div>
        </div>
      \`).join('');

      document.getElementById('accuse-suspect').innerHTML = c.suspects.map(s =>
        \`<option value="\${esc(s.id)}">\${s.avatar} \${esc(s.name)} — \${esc(s.role)}</option>\`
      ).join('');
      document.getElementById('accuse-evidence').innerHTML = evOptions;

      const vbox = document.getElementById('verdict-box');
      if (appState.latestAccusationResult) {
        const r = appState.latestAccusationResult;
        vbox.innerHTML = \`
          <div class="verdict-banner \${r.solved ? 'ok' : 'warn'}">
            <div>\${esc(r.verdictText)}</div>
            <div style="margin-top:6px;font-size:12px;">🏆 Điểm Suy Luận: <strong>\${r.score}/100</strong> — Hạng: <strong>\${esc(r.rank)}</strong></div>
          </div>
        \`;
      } else {
        vbox.innerHTML = '';
      }

      document.getElementById('ioc-box').innerHTML = \`
        <div>Các dấu vết số thu thập tại hiện trường (Sẵn sàng đẩy sang đồ thị <strong>OmniTrace OSINT Port 4090</strong>):</div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:4px;">
          \${(c.iocs || []).map(ioc => \`<span class="pill" style="font-family:monospace;">\${esc(ioc)}</span>\`).join('')}
        </div>
      \`;
    }

    async function inspectEv(evidenceId) {
      appState = await api('/api/evidence/inspect', 'POST', { evidenceId });
      renderAll();
    }

    async function askSuspect(suspectId, tactic) {
      const res = await api('/api/interrogate', 'POST', { suspectId, tactic });
      appState = res;
      if (res.lastEntry) {
        updatePolygraph(res.lastEntry);
      }
      renderAll();
    }

    async function presentEv(suspectId) {
      const sel = document.getElementById('ev-for-' + suspectId);
      const evidenceId = sel ? sel.value : null;
      const res = await api('/api/interrogate', 'POST', {
        suspectId,
        tactic: 'PRESENT_EVIDENCE',
        evidenceId
      });
      appState = res;
      if (res.lastEntry) {
        updatePolygraph(res.lastEntry);
      }
      renderAll();
    }

    function updatePolygraph(entry) {
      currentPoly = {
        bpm: entry.bpm || 80,
        gsr: entry.gsr || 30,
        deceptionProb: entry.deceptionProb || 20,
        subject: entry.speaker || 'Nghi phạm'
      };
      document.getElementById('poly-subject-label').textContent = 'Đang đo sinh trắc: ' + currentPoly.subject;
      document.getElementById('stat-bpm').textContent = currentPoly.bpm + ' BPM';
      document.getElementById('stat-gsr').textContent = currentPoly.gsr + ' μS';
      document.getElementById('stat-deception').textContent = currentPoly.deceptionProb + '%';
    }

    function animatePolygraph() {
      const canvas = document.getElementById('polygraph-canvas');
      if (canvas) {
        const ctx = canvas.getContext('2d');
        const w = canvas.width;
        const h = canvas.height;
        ctx.fillStyle = '#060911';
        ctx.fillRect(0, 0, w, h);

        ctx.strokeStyle = 'rgba(30, 41, 59, 0.7)';
        ctx.lineWidth = 1;
        for (let x = 0; x < w; x += 26) {
          ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
        }
        for (let y = 0; y < h; y += 26) {
          ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
        }

        // Sóng nhịp tim (Đỏ/Cam)
        const freq = currentPoly.bpm / 60;
        const amp = Math.min(42, 12 + (currentPoly.deceptionProb / 100) * 30);
        ctx.strokeStyle = currentPoly.deceptionProb > 75 ? '#ef4444' : '#38bdf8';
        ctx.lineWidth = 2;
        ctx.beginPath();
        for (let x = 0; x < w; x++) {
          const t = (x + waveTick) * 0.08 * freq;
          const spike = Math.sin(t) * Math.pow(Math.cos(t * 0.5), 4) * amp;
          const jitter = currentPoly.deceptionProb > 70 ? (Math.sin(x * 0.7 + waveTick) * 4) : 0;
          const y = h / 2 + spike + jitter;
          if (x === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        }
        ctx.stroke();
        waveTick += 3;
      }
      drawNoirCrimeScene();
      requestAnimationFrame(animatePolygraph);
    }

    // =========================================================================
    // ENGINE 2.5D CRIME SCENE CYBERPUNK 60FPS (THÁM TỬ ÁO MĂNG-TÔ + MƯA ĐÊM + MEDALLION BÁT GIÁC)
    // =========================================================================
    const bgImg = new Image();
    let bgReady = false;
    bgImg.onload = () => { bgReady = true; };
    bgImg.src = '/assets/crime-scene-bg.jpg';

    const noirPlayer = { x: 460, y: 278, targetX: 460, facing: 1, walk: 0, visor: 'NORMAL', pendingEvId: null };
    const noirMouse = { x: 480, y: 180 };
    const rainDrops = Array.from({ length: 55 }, (_, i) => ({
      x: (i * 23) % 960,
      y: (i * 19) % 330,
      len: 12 + (i % 9),
      spd: 5.5 + (i % 4)
    }));

    function setNoirVisor(mode) {
      noirPlayer.visor = mode;
      ['NORMAL', 'UV', 'CYBER'].forEach(m => {
        const b = document.getElementById('vbtn-' + m);
        if (b) b.classList.toggle('active', m === mode);
      });
    }

    window.addEventListener('keydown', (e) => {
      if (document.activeElement && ['INPUT', 'SELECT'].includes(document.activeElement.tagName)) return;
      if (e.key === '1') setNoirVisor('NORMAL');
      if (e.key === '2') setNoirVisor('UV');
      if (e.key === '3') setNoirVisor('CYBER');
    });

    function getEvidencePositions(evList) {
      const slots = [
        { x: 185, y: 185 },
        { x: 390, y: 155 },
        { x: 615, y: 170 },
        { x: 805, y: 185 }
      ];
      return (evList || []).map((ev, idx) => ({
        ev,
        x: slots[idx % slots.length].x,
        y: slots[idx % slots.length].y
      }));
    }

    function drawNoirCrimeScene() {
      const sc = document.getElementById('noirSceneCanvas');
      if (!sc || !appState || !appState.activeCase) return;
      const ctx = sc.getContext('2d');
      const w = sc.width;
      const h = sc.height;

      // 1. Nền Concept Art 16:9 kèm Parallax
      const px = ((noirMouse.x - w / 2) / w) * 14;
      if (bgReady) {
        ctx.drawImage(bgImg, -px - 10, -6, w + 20, h + 12);
        ctx.fillStyle = noirPlayer.visor === 'UV'
          ? 'rgba(38, 12, 78, 0.58)'
          : noirPlayer.visor === 'CYBER'
          ? 'rgba(4, 28, 38, 0.58)'
          : 'rgba(6, 10, 20, 0.36)';
        ctx.fillRect(0, 0, w, h);
      } else {
        ctx.fillStyle = '#070b14';
        ctx.fillRect(0, 0, w, h);
      }

      // 2. Hạt mưa Cyberpunk ngoài cửa kính & sàn phản quang
      ctx.strokeStyle = noirPlayer.visor === 'UV' ? 'rgba(192,132,252,0.35)' : 'rgba(103,232,249,0.28)';
      ctx.lineWidth = 1.2;
      for (const r of rainDrops) {
        r.x -= 1.1;
        r.y += r.spd;
        if (r.y > h) { r.y = -10; r.x = Math.random() * w; }
        ctx.beginPath();
        ctx.moveTo(r.x, r.y);
        ctx.lineTo(r.x - 3, r.y + r.len);
        ctx.stroke();
      }

      // 3. Vẽ các Medallion Bát Giác Vật Chứng Hiện Trường
      const nodes = getEvidencePositions(appState.activeCase.evidence);
      for (const item of nodes) {
        const { ev, x, y } = item;
        const done = ev.inspected;
        const col = done ? '#10b981' : noirPlayer.visor === 'UV' ? '#e879f9' : '#f59e0b';
        const hov = Math.hypot(noirMouse.x - x, noirMouse.y - y) <= 34;

        ctx.save();
        ctx.translate(x, y);
        ctx.rotate(waveTick * 0.008 * (done ? 0.4 : 1));
        ctx.strokeStyle = col;
        ctx.lineWidth = hov ? 2.4 : 1.6;
        ctx.setLineDash([7, 5]);
        ctx.beginPath();
        ctx.arc(0, 0, hov ? 26 : 22, 0, Math.PI * 2);
        ctx.stroke();
        ctx.restore();

        // Nút Bát giác
        ctx.save();
        ctx.fillStyle = 'rgba(8, 13, 26, 0.92)';
        ctx.strokeStyle = hov ? '#ffffff' : col;
        ctx.lineWidth = 2;
        ctx.beginPath();
        for (let k = 0; k < 8; k++) {
          const a = (Math.PI * 2 * k) / 8 + Math.PI / 8;
          const rx = x + Math.cos(a) * 16;
          const ry = y + Math.sin(a) * 16;
          if (k === 0) ctx.moveTo(rx, ry);
          else ctx.lineTo(rx, ry);
        }
        ctx.closePath();
        ctx.fill();
        ctx.stroke();

        ctx.fillStyle = col;
        ctx.font = 'bold 11px Consolas, monospace';
        ctx.textAlign = 'center';
        ctx.fillText(done ? '✓' : '◈', x, y + 4);

        // Nhãn vát góc gọn gàng
        const shortName = ev.name.length > 22 ? ev.name.slice(0, 21) + '…' : ev.name;
        const bw = Math.max(118, shortName.length * 6.5 + 22);
        ctx.fillStyle = 'rgba(6, 11, 23, 0.92)';
        ctx.strokeStyle = col;
        ctx.lineWidth = 1.2;
        ctx.fillRect(x - bw / 2, y + 22, bw, 20);
        ctx.strokeRect(x - bw / 2, y + 22, bw, 20);
        ctx.fillStyle = done ? '#a7f3d0' : '#f8fafc';
        ctx.font = 'bold 10.5px "Segoe UI", sans-serif';
        ctx.fillText(shortName, x, y + 35);
        ctx.restore();
      }

      // 4. Cập nhật & Vẽ Thám Tử Áo Măng-tô + Chùm Đèn Pin Pháp Y
      const dx = noirPlayer.targetX - noirPlayer.x;
      if (Math.abs(dx) > 3) {
        noirPlayer.x += Math.sign(dx) * Math.min(4.2, Math.abs(dx));
        noirPlayer.facing = dx >= 0 ? 1 : -1;
        noirPlayer.walk += 0.25;
      } else if (noirPlayer.pendingEvId) {
        const eid = noirPlayer.pendingEvId;
        noirPlayer.pendingEvId = null;
        inspectEv(eid);
      }

      // Chùm đèn pin
      ctx.save();
      const beamAng = Math.atan2(noirMouse.y - (noirPlayer.y - 36), noirMouse.x - noirPlayer.x);
      const grad = ctx.createRadialGradient(noirPlayer.x, noirPlayer.y - 36, 6, noirPlayer.x, noirPlayer.y - 36, 240);
      if (noirPlayer.visor === 'UV') {
        grad.addColorStop(0, 'rgba(217, 70, 239, 0.42)');
        grad.addColorStop(1, 'rgba(217, 70, 239, 0)');
      } else if (noirPlayer.visor === 'CYBER') {
        grad.addColorStop(0, 'rgba(6, 182, 212, 0.42)');
        grad.addColorStop(1, 'rgba(6, 182, 212, 0)');
      } else {
        grad.addColorStop(0, 'rgba(251, 191, 36, 0.36)');
        grad.addColorStop(1, 'rgba(251, 191, 36, 0)');
      }
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.moveTo(noirPlayer.x, noirPlayer.y - 36);
      ctx.arc(noirPlayer.x, noirPlayer.y - 36, 240, beamAng - 0.32, beamAng + 0.32);
      ctx.closePath();
      ctx.fill();
      ctx.restore();

      // Hình nhân Thám tử Noir 2.5D (Mũ Fedora + Áo Măng-tô + Kính Cyber)
      ctx.save();
      ctx.translate(noirPlayer.x, noirPlayer.y);
      ctx.scale(noirPlayer.facing, 1);
      const legSwing = Math.sin(noirPlayer.walk) * 4;
      ctx.fillStyle = 'rgba(0,0,0,0.55)';
      ctx.beginPath();
      ctx.ellipse(0, 4, 18, 5, 0, 0, Math.PI * 2);
      ctx.fill();
      // Chân
      ctx.fillStyle = '#1e293b';
      ctx.fillRect(-7 + legSwing, -16, 5, 18);
      ctx.fillRect(2 - legSwing, -16, 5, 18);
      // Áo măng-tô
      ctx.fillStyle = '#334155';
      ctx.strokeStyle = '#94a3b8';
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      ctx.roundRect(-11, -44, 22, 30, 5);
      ctx.fill();
      ctx.stroke();
      // Cổ áo dựng & Cà vạt hổ phách
      ctx.fillStyle = '#f59e0b';
      ctx.fillRect(-1, -41, 3, 14);
      // Đầu & Mũ Fedora
      ctx.fillStyle = '#e2e8f0';
      ctx.beginPath();
      ctx.arc(0, -52, 8, 0, Math.PI * 2);
      ctx.fill();
      // Kính Cyber phát sáng
      ctx.fillStyle = '#06b6d4';
      ctx.fillRect(1, -54, 7, 3.5);
      // Mũ Fedora
      ctx.fillStyle = '#0f172a';
      ctx.fillRect(-13, -59, 26, 3.5);
      ctx.fillRect(-8, -66, 16, 7);
      ctx.restore();
    }

    window.addEventListener('DOMContentLoaded', async () => {
      const sc = document.getElementById('noirSceneCanvas');
      if (sc) {
        sc.addEventListener('mousemove', (e) => {
          const r = sc.getBoundingClientRect();
          noirMouse.x = ((e.clientX - r.left) * sc.width) / r.width;
          noirMouse.y = ((e.clientY - r.top) * sc.height) / r.height;
        });
        sc.addEventListener('click', (e) => {
          if (!appState || !appState.activeCase) return;
          const r = sc.getBoundingClientRect();
          const cx = ((e.clientX - r.left) * sc.width) / r.width;
          const cy = ((e.clientY - r.top) * sc.height) / r.height;
          const nodes = getEvidencePositions(appState.activeCase.evidence);
          for (const item of nodes) {
            if (Math.hypot(cx - item.x, cy - item.y) <= 38) {
              noirPlayer.targetX = item.x;
              noirPlayer.pendingEvId = item.ev.id;
              return;
            }
          }
          noirPlayer.targetX = Math.max(70, Math.min(890, cx));
          noirPlayer.pendingEvId = null;
        });
      }

      appState = await api('/api/state');
      renderAll();
      animatePolygraph();

      document.getElementById('sel-case').addEventListener('change', async (e) => {
        appState = await api('/api/case/select', 'POST', { caseId: e.target.value });
        renderAll();
      });

      document.getElementById('btn-gen-case').addEventListener('click', async () => {
        appState = await api('/api/case/generate', 'POST', {});
        renderAll();
      });

      document.getElementById('btn-submit-accuse').addEventListener('click', async () => {
        const suspectId = document.getElementById('accuse-suspect').value;
        const evidenceId = document.getElementById('accuse-evidence').value;
        const notes = document.getElementById('accuse-notes').value;
        appState = await api('/api/accuse', 'POST', { suspectId, evidenceId, notes });
        renderAll();
      });

      document.getElementById('btn-push-osint').addEventListener('click', async () => {
        const res = await api('/api/osint/push', 'POST', {});
        appState = res;
        alert(\`🕸️ Đã đẩy \${res.osintEvent?.pushedCount || 4} IOC Pháp y Số của vụ án sang OmniTrace OSINT (Port 4090)!\`);
        renderAll();
      });
    });
  </script>
</body>
</html>`;
}

// ============================================================================
// 4. HTTP SERVER & REST API ENDPOINTS
// ============================================================================

function buildFullState(extra = {}) {
  return {
    ok: true,
    port: PORT,
    activeCaseId,
    activeCase: getActiveCase(),
    casesCatalog: casesCatalog.map((c) => ({
      id: c.id,
      code: c.code,
      title: c.title,
      location: c.location
    })),
    interrogationLogs,
    latestAccusationResult,
    osintPushHistory,
    ...extra
  };
}

function sendJson(res, status, data) {
  const buf = Buffer.from(JSON.stringify(data), 'utf8');
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Length': buf.length
  });
  res.end(buf);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch (e) {
        reject(new Error('JSON không hợp lệ'));
      }
    });
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    });
    return res.end();
  }

  const parsedUrl = new URL(req.url, `http://localhost:${PORT}`);
  const pathname = parsedUrl.pathname;

  try {
    if (pathname === '/' && req.method === 'GET') {
      const html = renderHtmlPage();
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(html);
    }

    if (pathname === '/api/state' && req.method === 'GET') {
      return sendJson(res, 200, buildFullState());
    }

    if (pathname === '/api/case/select' && req.method === 'POST') {
      const body = await readBody(req);
      const found = casesCatalog.find((c) => c.id === body.caseId);
      if (!found) return sendJson(res, 404, { ok: false, error: 'Không tìm thấy hồ sơ vụ án' });
      activeCaseId = found.id;
      latestAccusationResult = null;
      return sendJson(res, 200, buildFullState());
    }

    if (pathname === '/api/case/generate' && req.method === 'POST') {
      const newCase = generateProceduralCase();
      casesCatalog.unshift(newCase);
      activeCaseId = newCase.id;
      latestAccusationResult = null;
      return sendJson(res, 200, buildFullState({ generatedCase: newCase }));
    }

    if (pathname === '/api/evidence/inspect' && req.method === 'POST') {
      const body = await readBody(req);
      const inspectedEvidence = inspectEvidence(body.evidenceId);
      return sendJson(res, 200, buildFullState({ inspectedEvidence }));
    }

    if (pathname === '/api/interrogate' && req.method === 'POST') {
      const body = await readBody(req);
      const lastEntry = interrogateSuspect(body);
      return sendJson(res, 200, buildFullState({ lastEntry }));
    }

    if (pathname === '/api/accuse' && req.method === 'POST') {
      const body = await readBody(req);
      const verdict = submitAccusation(body);
      return sendJson(res, 200, buildFullState({ verdict }));
    }

    if (pathname === '/api/osint/push' && req.method === 'POST') {
      const osintEvent = await pushCaseIocsToOsint();
      return sendJson(res, 200, buildFullState({ osintEvent }));
    }

    if (pathname.startsWith('/assets/') && req.method === 'GET') {
      const assetPath = path.join(PUBLIC_DIR, pathname);
      if (assetPath.startsWith(PUBLIC_DIR) && fs.existsSync(assetPath) && fs.statSync(assetPath).isFile()) {
        const ext = path.extname(assetPath).toLowerCase();
        const mime = ext === '.jpg' || ext === '.jpeg' ? 'image/jpeg' : ext === '.png' ? 'image/png' : 'application/octet-stream';
        res.writeHead(200, { 'Content-Type': mime });
        return fs.createReadStream(assetPath).pipe(res);
      }
    }

    sendJson(res, 404, { ok: false, error: 'Endpoint không tồn tại' });
  } catch (err) {
    sendJson(res, 400, { ok: false, error: err.message || 'Lỗi xử lý yêu cầu' });
  }
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`🕵️‍♂️ NoirDetective đang chạy tại http://localhost:${PORT}`);
  });
}

module.exports = { server };

