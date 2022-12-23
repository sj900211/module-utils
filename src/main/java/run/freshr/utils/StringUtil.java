package run.freshr.utils;

import static java.util.Optional.ofNullable;

import java.text.DecimalFormat;
import java.util.Objects;
import java.util.Random;
import lombok.extern.slf4j.Slf4j;

/**
 * 문자 Util
 *
 * @author FreshR
 * @apiNote 문자 데이터를 쉽게 사용하기 위한 Util
 * @since 2022. 12. 23. 오후 4:23:59
 */
@Slf4j
public class StringUtil {

  /**
   * 음절 목록화
   *
   * @param value 음절 목록으로 변환할 문자
   * @return 변환한 음절 목록
   * @apiNote 문자를 음절 목록으로 변환하여 반환
   * @author FreshR
   * @since 2022. 12. 23. 오후 4:23:59
   */
  public static char[] toChar(final String value) {
    log.debug("StringUtil.toChar");
    log.debug("value = " + value);

    char[] result = Objects.toString(value).toCharArray();

    log.debug("result = " + result);

    return result;
  }

  /**
   * 앞 자리수 채우기
   *
   * @param value 값
   * @param size  자리수
   * @return 자리수만큼 0으로 앞 공간이 채워진 문자
   * @apiNote 값을 자리수만큼 남는 앞 공간을 0으로 채워서 반환
   * @author FreshR
   * @since 2022. 12. 23. 오후 4:23:59
   */
  public static String padding(final Number value, final Integer size) {
    log.debug("StringUtil.padding");
    log.debug("value = " + value + ", size = " + size);

    String result = padding(value, "0", size);

    log.debug("result = " + result);

    return result;
  }

  /**
   * 앞 자리수 채우기
   *
   * @param value       값
   * @param paddingWord 빈 자리수에 채워질 문자
   * @param size        자리수
   * @return 자리수만큼 빈 자리수에 채워질 문자로 앞 공간이 채워진 문자
   * @apiNote 값을 자리수만큼 남는 앞 공간을 자리수에 채워질 문자로 채워서 반환
   * @author FreshR
   * @since 2022. 12. 23. 오후 4:23:59
   */
  public static String padding(final Number value, final String paddingWord, final Integer size) {
    log.debug("StringUtil.padding");
    log.debug("value = " + value + ", paddingWord = " + paddingWord + ", size = " + size);

    String result = new DecimalFormat(String.valueOf(paddingWord)
        .repeat(Math.max(0, size)))
        .format(ofNullable(value).orElse(0).longValue());

    log.debug("result = " + result);

    return result;
  }

  /**
   * 세 자리 콤마
   *
   * @param value 값
   * @return 세자리마다 콤마가 들어간 값
   * @apiNote 전달된 값을 세자리마다 콤마를 추가해서 반환
   * @author FreshR
   * @since 2022. 12. 23. 오후 4:23:59
   */
  public static String comma(final Number value) {
    log.debug("StringUtil.comma");
    log.debug("value = " + value);

    String result = separate(value.toString(), 3, ",");

    log.debug("result = " + result);

    return result;
  }

  /**
   * 구문 문자 추가
   *
   * @param value     값
   * @param length    자리수
   * @param separator 구분 문자
   * @return 전달된 자리수마다 전달된 구분 문자를 추가한 값
   * @apiNote 전달된 값에 전달된 자리수마다 전달된 구분 문자를 추가한 값을 반환
   * @author FreshR
   * @since 2022. 12. 23. 오후 4:23:59
   */
  public static String separate(final String value, final Number length, final String separator) {
    log.debug("StringUtil.separate");
    log.debug("value = " + value + ", length = " + length + ", separator = " + separator);

    StringBuffer reverseValue = new StringBuffer(value).reverse();
    int reverseLength = reverseValue.toString().length();

    StringBuilder stringBuilder = new StringBuilder();

    int number = ofNullable(length).orElse(0).intValue();

    for (int i = 0; i < reverseLength; i++) {
      if (i % number == 0 && i != 0) {
        stringBuilder.append(separator);
      }

      stringBuilder.append(reverseValue.charAt(i));
    }

    String result = stringBuilder.reverse().toString();

    log.debug("result = " + result);

    return result;
  }

  /**
   * 임의의 16진수 문자
   *
   * @param limit 길이
   * @return 전달된 길이의 랜덤한 16진수 문자
   * @apiNote 전달된 길이만큼 랜덤한 16진수 문자를 생성해서 반환
   * @author FreshR
   * @since 2022. 12. 23. 오후 4:23:59
   */
  public static String hex(final Integer limit) {
    log.debug("StringUtil.hex");
    log.debug("limit = " + limit);

    StringBuilder hex = new StringBuilder();

    for (int i = 0; i < limit; i++) {
      hex.append(Integer.toHexString(new Random().nextInt(16)));
    }

    String result = hex.toString();

    log.debug("result = " + result);

    return result;
  }

  /**
   * 임의의 문자
   *
   * @param limit 길이
   * @return 전달된 길이의 랜덤한 정수 문자
   * @apiNote 전달된 길이만큼 랜덤한 정수 문자를 생성해서 반환
   * @author FreshR
   * @since 2022. 12. 23. 오후 4:23:59
   */
  public static String random(final Integer limit) {
    log.debug("StringUtil.random");
    log.debug("limit = " + limit);

    StringBuilder random = new StringBuilder();

    for (int i = 0; i < limit; i++) {
      random.append(new Random().nextInt(10));
    }

    String result = random.toString();

    log.debug("result = " + result);

    return result;
  }

}
